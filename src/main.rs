use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process, str,
    sync::{Arc, Mutex, OnceLock},
    thread,
};

use anyhow::{Context, Result};
use bstr::io::BufReadExt;
use clap::Parser;
use colored::Colorize;
use crossbeam_channel as channel;
use figment::{
    providers::{Format, Toml},
    Figment,
};
use file_type_enum::FileType;
use home_dir::HomeDirExt;
use lscolors::{LsColors, Style};
use lz4::EncoderBuilder;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

static UPPER_RE: OnceLock<Regex> = OnceLock::new();

static PROJECT_CONFIG_TEMPLATE: &str = r#"
description = ""

# Directories to index.
dirs = [
  # "~/first/dir",
  # "/second/dir"
]

"#;

static PROJECT_IGNORE_TEMPLATE: &str = r#"# Dirs / files to ignore.
# Use the same syntax as gitignore(5).
# Common patterns:
#
# .git
# *~
# target/
"#;

macro_rules! print_err {
    ($($err:tt)*) => ({
        eprintln!("{}: {}", "Error".red().bold(), format!($($err)*));
    })
}

macro_rules! greenify {
    ($g:expr) => {
        $g.display().to_string().green()
    };
}

#[derive(Parser)]
#[command(name = "lolcate")]
#[command(version = "0.2")]
pub struct Args {
    /// Create a database
    #[arg(long, conflicts_with_all = &["pattern", "update", "info"])]
    pub create: bool,

    /// Display configuration information and existing databases
    #[arg(long, conflicts_with_all = &["pattern", "update", "create", "database"])]
    pub info: bool,

    /// Update database
    #[arg(short = 'u', long, conflicts_with_all = &["pattern", "create", "info"])]
    pub update: bool,

    /// Database to be used / created
    #[arg(long = "db", default_value = "default")]
    pub database: String,

    /// Query / update all databases
    #[arg(long, conflicts_with_all = &["create", "info"])]
    pub all: bool,

    /// Search case-insensitively [default: smart-case]
    #[arg(short = 'i', long = "ignore-case", conflicts_with_all = &["create", "info", "update"])]
    pub ignore_case: bool,

    /// Match only basename against PATTERN
    #[arg(short = 'b', long = "basename", conflicts_with_all = &["create", "info", "update"])]
    pub basename_pattern: Option<Vec<String>>,

    /// PATTERN
    #[clap(required = false)]
    pub pattern: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LocalConfig {
    pub description: String,
    pub dirs: Vec<PathBuf>,
}

pub enum WorkerResult {
    Entry(PathBuf),
    Error(ignore::Error),
}

pub enum DirEntry {
    Normal(ignore::DirEntry),
    BrokenSymlink(PathBuf),
}

impl DirEntry {
    pub fn path(&self) -> &Path {
        match self {
            DirEntry::Normal(e) => e.path(),
            DirEntry::BrokenSymlink(pathbuf) => pathbuf.as_path(),
        }
    }

    pub fn file_type(&self) -> Option<fs::FileType> {
        match self {
            DirEntry::Normal(e) => e.file_type(),
            DirEntry::BrokenSymlink(pathbuf) => {
                pathbuf.symlink_metadata().map(|m| m.file_type()).ok()
            }
        }
    }
}

pub fn lolcate_config_path() -> PathBuf {
    let xdg_dir = xdg::BaseDirectories::with_prefix("lolcate")
        .context("Failed get config directory")
        .unwrap();

    xdg_dir.get_config_home()
}

pub fn lolcate_data_path() -> PathBuf {
    let xdg_dir = xdg::BaseDirectories::with_prefix("lolcate")
        .context("Failed get config directory")
        .unwrap();

    xdg_dir.get_data_home()
}

fn get_db_config(path: &Path) -> Result<LocalConfig> {
    let xdg_dir =
        xdg::BaseDirectories::with_prefix("lolcate").context("Failed get config directory")?;

    let filename = xdg_dir.place_config_file(path)?;

    Ok(Figment::new().merge(Toml::file(filename)).extract()?)
}

fn config_fn(db_name: &str) -> PathBuf {
    let mut _fn = lolcate_config_path();
    _fn.push(db_name);
    _fn.push("config.toml");
    _fn
}

fn db_fn(db_name: &str) -> PathBuf {
    let mut _fn = lolcate_data_path();
    _fn.push(db_name);
    _fn.push("db.lz4");
    _fn
}

fn ignores_fn(db_name: &str) -> PathBuf {
    let mut _fn = lolcate_config_path();
    _fn.push(db_name);
    _fn.push("ignores");
    _fn
}

fn create_database(db_name: &str) -> io::Result<()> {
    let mut db_dir = lolcate_data_path();

    db_dir.push(db_name);

    if db_dir.exists() {
        print_err!("database {} already exists", &db_name.green());
        process::exit(1);
    }

    let config_fn = config_fn(db_name);
    fs::create_dir_all(config_fn.parent().unwrap())?;

    let mut f = fs::File::create(&config_fn)?;
    f.write_all(PROJECT_CONFIG_TEMPLATE.as_bytes())?;

    let ignores_fn = ignores_fn(db_name);
    f = fs::File::create(&ignores_fn)?;
    f.write_all(PROJECT_IGNORE_TEMPLATE.as_bytes())?;

    println!("Created database {}.\nPlease edit:", db_name.green().bold());
    println!("- the configuration file: {}", greenify!(config_fn));
    println!("- the ignores file:       {}", greenify!(ignores_fn));
    process::exit(0);
}

fn database_names(path: PathBuf) -> Vec<String> {
    let mut _dbs: Vec<String> = Vec::new();
    let walker = walkdir::WalkDir::new(path).min_depth(1).into_iter();
    for entry in walker.filter_entry(|e| e.file_type().is_dir()) {
        if let Some(db_name) = entry.unwrap().file_name().to_str() {
            _dbs.push(db_name.to_string());
        }
    }
    _dbs
}

fn info_databases() -> io::Result<()> {
    struct DatabaseInfo {
        name: String,
        description: String,
        config: String,
        ignores: String,
        data: String,
    }

    let mut databases: Vec<DatabaseInfo> = vec![];

    let walker = walkdir::WalkDir::new(lolcate_config_path())
        .min_depth(1)
        .into_iter();

    for entry in walker.filter_entry(|e| e.file_type().is_dir()) {
        if let Some(db_name) = entry.unwrap().file_name().to_str() {
            let config_fn = config_fn(db_name);
            let config = get_db_config(&config_fn).unwrap();
            let mut db_fn = lolcate_data_path();

            db_fn.push(db_name);

            databases.push(DatabaseInfo {
                name: db_name.to_string(),
                description: config.description,
                config: config_fn.display().to_string(),
                ignores: ignores_fn(db_name).display().to_string(),
                data: db_fn.display().to_string(),
            });
        }
    }

    match databases.len() {
        0 => println!("{}", "No databases found".cyan()),
        _ => {
            println!("{}", "Databases:".cyan());
            for db in databases {
                println!("  {}", db.name.green());
                println!("    Description: {}", db.description);
                println!("         Config: {}", db.config);
                println!("        Ignores: {}", db.ignores);
                println!("  Database File: {}", db.data);
            }
        }
    };

    println!();
    Ok(())
}

pub fn walker(config: &LocalConfig, database: &str) -> ignore::WalkParallel {
    let paths: Vec<PathBuf> = config
        .dirs
        .iter()
        .map(|p| p.expand_home().unwrap())
        .collect();

    let mut wd = ignore::WalkBuilder::new(&paths[0]);

    wd.hidden(false)
        .hidden(false)
        .follow_links(false)
        .git_global(true);

    for path in &paths[1..] {
        if path.exists() {
            wd.add(path);
        }
    }

    wd.add_ignore(ignores_fn(database));
    wd.threads(num_cpus::get());
    wd.build_parallel()
}

fn update_database(db_name: &str) -> io::Result<()> {
    let config_fn = config_fn(db_name);
    if !config_fn.exists() {
        print_err!(
            "Config file not found for database {}.\n Perhaps you forgot to run lolcate --create \
             {} ?",
            &db_name.green(),
            &db_name.green()
        );
        process::exit(1);
    }

    let config = get_db_config(&config_fn).unwrap();

    if config.dirs.is_empty() {
        print_err!(
            "{} needs at least one directory to scan",
            greenify!(config_fn)
        );
        process::exit(1);
    }

    let db_path = db_fn(db_name);

    fs::create_dir_all(db_path.parent().unwrap())?;

    let output_fn = fs::File::create(db_path)?;
    let (tx, rx) = channel::bounded::<WorkerResult>(8000);

    println!("{} {}...", "Updating".green().bold(), db_name);

    let stdout_thread = thread::spawn(move || {
        let mut encoder = EncoderBuilder::new()
            .level(3)
            .block_mode(lz4::BlockMode::Linked)
            .block_size(lz4::BlockSize::Max256KB)
            .build(output_fn)?;

        for entry in rx {
            match entry {
                WorkerResult::Entry(value) => {
                    if let Ok(t) = FileType::symlink_read_at(&value) {
                        writeln!(encoder, "{},,,{}", &value.display(), t).unwrap();
                    }
                }
                WorkerResult::Error(err) => {
                    print_err!("{}", err.to_string());
                }
            }
        }
        let (_output, result) = encoder.finish();
        result
    });

    let cache_dir: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));

    walker(&config, db_name).run(|| {
        let tx = tx.clone();
        let ig = cache_dir.clone();

        Box::new(move |_entry| {
            //: Result<ignore::DirEntry,ignore::Error>

            // Taken from sharkdp/fd
            let entry = match _entry {
                Ok(e) => DirEntry::Normal(e),
                Err(ignore::Error::WithPath { path, err: error }) => match error.as_ref() {
                    ignore::Error::Io(io_err)
                        if io_err.kind() == io::ErrorKind::NotFound
                            && path
                                .symlink_metadata()
                                .ok()
                                .map_or(false, |m| m.file_type().is_symlink()) =>
                    {
                        DirEntry::BrokenSymlink(path)
                    }
                    _ => {
                        return match tx.send(WorkerResult::Error(ignore::Error::WithPath {
                            path,
                            err: error,
                        })) {
                            Ok(_) => ignore::WalkState::Continue,
                            Err(_) => ignore::WalkState::Quit,
                        }
                    }
                },
                Err(err) => {
                    return match tx.send(WorkerResult::Error(err)) {
                        Ok(_) => ignore::WalkState::Continue,
                        Err(_) => ignore::WalkState::Quit,
                    }
                }
            };

            if let Some(mut ignored) = ig.lock().ok() {
                if cachedir::is_tagged(&entry.path()).unwrap_or(false) {
                    ignored.insert(entry.path().to_owned());
                    return ignore::WalkState::Continue;
                }

                // Check if the parent directory is ignored.
                if ignored
                    .iter()
                    .any(|ignored_path| entry.path().starts_with(ignored_path))
                {
                    return ignore::WalkState::Continue;
                }
            }

            match tx.send(WorkerResult::Entry(entry.path().to_owned())) {
                Ok(_) => ignore::WalkState::Continue,
                Err(_) => ignore::WalkState::Quit,
            }
        })
    });

    drop(tx);
    stdout_thread.join().unwrap()
}

fn build_regex(pattern: String, ignore_case: bool) -> Regex {
    let re = UPPER_RE.get_or_init(|| Regex::new(r"[[:upper:]]").unwrap());

    match RegexBuilder::new(&pattern)
        .case_insensitive(ignore_case || !re.is_match(&pattern))
        .build()
    {
        Ok(re) => re,
        Err(error) => {
            print_err!("invalid regex: {}", error);
            process::exit(1);
        }
    }
}

fn lookup_database(db_name: &str, patterns_re: &[Regex]) -> std::io::Result<()> {
    let db_file = db_fn(db_name);
    if !db_file.parent().unwrap().exists() {
        print_err!(
            "Database {} doesn't exist. Perhaps you forgot to run lolcate --create {} ?",
            &db_name.green(),
            &db_name.green()
        );
        process::exit(1);
    }

    if !db_file.exists() {
        print_err!(
            "Database {} is empty. Perhaps you forgot to run lolcate --update {} ?",
            &db_name.green(),
            &db_name.green()
        );
        process::exit(1);
    }

    let input_file = fs::File::open(db_file)?;
    let decoder = lz4::Decoder::new(input_file)?;
    let mut reader = io::BufReader::new(decoder);

    let stdout = io::stdout();
    let lock = stdout.lock();
    let mut w = io::BufWriter::new(lock); // DEFAULT_BUF_SIZE: usize = 8 * 1024;

    reader.for_byte_line(|_line| {
        let line = str::from_utf8(_line).unwrap();

        if !patterns_re.iter().all(|re| re.is_match(line)) {
            return Ok(true);
        }

        {
            let _ = w.write_all(fmt_output(line.split(",,,").collect::<Vec<_>>()[0]).as_bytes());
            let _ = w.write_all(b"\n");
        }
        Ok(true)
    })
}

fn fmt_output<P: AsRef<Path>>(path: P) -> String {
    let lscolors = LsColors::from_env().unwrap_or_default();

    lscolors
        .style_for_path_components(path.as_ref())
        .fold(Vec::new(), |mut acc, (component, style)| {
            acc.push(
                style
                    .map_or(ansi_term::Color::Blue.bold(), Style::to_ansi_term_style)
                    .paint(component.to_string_lossy())
                    .to_string(),
            );
            acc
        })
        .join("")
}

fn main() -> Result<()> {
    let args = Args::parse();

    let databases = if args.all {
        database_names(lolcate_config_path())
    } else {
        vec![args.database.clone()]
    };

    if args.create {
        create_database(&args.database)?;
        process::exit(0);
    }

    if args.update {
        for db in databases {
            update_database(&db)?;
        }
        process::exit(0);
    }

    if args.info {
        info_databases()?;
        process::exit(0);
    }

    // lookup
    let ignore_case = args.ignore_case;

    let patterns_re = args
        .pattern
        .iter()
        .map(|p| build_regex(p.to_string(), ignore_case));

    let bn_patterns_re = args
        .basename_pattern
        .unwrap_or_default()
        .iter()
        .map(|p| build_regex(format!("/[^/]*{}[^/]*$", p), ignore_case))
        .collect::<Vec<_>>();

    let chained = &patterns_re.chain(bn_patterns_re).collect::<Vec<_>>();

    for db_name in databases {
        lookup_database(&db_name, chained)?;
    }

    Ok(())
}
