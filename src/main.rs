use std::{
    collections::HashMap,
    env, fs,
    io::{self, prelude::*, Write},
    path::{Path, PathBuf},
    process, str, thread,
};

use anyhow::Result;
use bstr::io::BufReadExt;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use crossbeam_channel as channel;
use file_type_enum::FileType;
use lscolors::{LsColors, Style};
use lz4::EncoderBuilder;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use toml::de::Error;

static GLOBAL_CONFIG_TEMPLATE: &str = r#"[types]
# Definition of custom path name types
# Examples:
img = ".*\\.(jp.?g|png|gif|JP.?G)$"
video = ".*\\.(flv|mp4|mp.?g|avi|wmv|mkv|3gp|m4v|asf|webm)$"
doc = ".*\\.(pdf|chm|epub|djvu?|mobi|azw3|odf|ods|md|tex|txt|adoc)$"
audio = ".*\\.(mp3|m4a|flac|ogg)$"

"#;

static PROJECT_CONFIG_TEMPLATE: &str = r#"
description = ""

# Directories to index.
dirs = [
  # "~/first/dir",
  # "/second/dir"
]

# Set to true if you want to ignore hidden files and directories
ignore_hidden = false

# Set to true if you want to ignore missing directories
ignore_missing = false

# Set to true to read .gitignore files and ignore matching files
gitignore = false

# Colored output (optional '#' or '0x' prefix)
# color = "FF5813"

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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum MimeChoices {
    F,
    D,
    Dir,
    File,
    #[default]
    Any,
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

    /// One or several file types to search, separated with commas
    #[arg(short = 't', long)]
    pub types: Option<String>,

    /// Filter based on file type
    #[arg(
        value_enum,
        short = 'm',
        long,
        default_value = "any",
        rename_all = "lowercase"
    )]
    pub mime: Option<MimeChoices>,

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
pub struct Config {
    pub description: String,
    #[serde(deserialize_with = "deserialize::deserialize")]
    pub dirs: Vec<PathBuf>,
    #[serde(default)]
    pub gitignore: bool,
    pub ignore_hidden: bool,
    pub ignore_missing: bool,
    pub color: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GlobalConfig {
    pub(crate) types: HashMap<String, String>,
}

pub(crate) fn read_toml_file<P: ?Sized, T>(path: &P, buffer: &mut String) -> Result<T, Error>
where
    P: AsRef<Path>,
    T: serde::de::DeserializeOwned,
{
    let mut configuration_file: fs::File = match fs::OpenOptions::new().read(true).open(path) {
        Ok(val) => val,
        Err(_e) => {
            eprintln!("Cannot open file {}", path.as_ref().display());
            process::exit(1);
        }
    };

    match configuration_file.read_to_string(buffer) {
        Ok(_bytes) => toml::from_str(buffer),
        Err(error) => panic!(
            "The data in this stream is not valid UTF-8.\nSee error: '{}'\n",
            error
        ),
    }
}

mod deserialize {
    use serde::de::{Deserialize, Deserializer};
    use std::path;

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<path::PathBuf>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Vec::<String>::deserialize(deserializer)?;
        s.into_iter()
            .map(|s| {
                return expanduser::expanduser(s).map_err(serde::de::Error::custom);
            })
            .collect()
    }
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
    let mut path = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home::home_dir().map(|d| d.join(".config")))
        .unwrap();

    path.push("lolcate");
    path
}

pub fn lolcate_data_path() -> PathBuf {
    let mut path = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home::home_dir().map(|d| d.join(".local").join("share")))
        .unwrap();

    path.push("lolcate");
    path
}

fn get_db_config(toml_file: &Path) -> Config {
    let mut buffer = String::new();
    let config: Config = match read_toml_file(&toml_file, &mut buffer) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Invalid TOML: {}", error);
            process::exit(1);
        }
    };
    config
}

fn create_global_config_if_needed() -> io::Result<()> {
    let _fn = global_config_fn();
    if !_fn.exists() {
        fs::create_dir_all(_fn.parent().unwrap())?;
        let mut f = fs::File::create(&_fn)?;
        f.write_all(GLOBAL_CONFIG_TEMPLATE.as_bytes())?;
    }
    Ok(())
}

fn get_global_config(toml_file: &Path) -> GlobalConfig {
    let mut buffer = String::new();
    let config: GlobalConfig = match read_toml_file(&toml_file, &mut buffer) {
        Ok(config) => config,
        Err(error) => {
            print_err!("invalid TOML: {}", error);
            process::exit(1);
        }
    };
    config
}

fn get_types_map() -> HashMap<String, String> {
    let _fn = global_config_fn();
    let _config = get_global_config(&_fn);
    _config.types
}

fn check_db_config(config: &Config, toml_file: &Path) {
    // Check config
    if config.dirs.is_empty() {
        print_err!(
            "{} needs at least one directory to scan",
            greenify!(toml_file)
        );
        process::exit(1);
    }

    for dir in &config.dirs {
        if !dir.exists() && !config.ignore_missing {
            print_err!("the specified dir {} doesn't exist.", greenify!(dir));
            process::exit(1);
        }
        if !dir.is_dir() && !config.ignore_missing {
            print_err!(
                "the specified path {} is not a directory or cannot be accessed",
                greenify!(dir)
            );
            process::exit(1);
        }
    }
}

fn global_config_fn() -> PathBuf {
    let mut _fn = lolcate_config_path();
    _fn.push("config.toml");
    _fn
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
    let mut db_data: Vec<(String, String, String, String, String)> = Vec::new();
    let walker = walkdir::WalkDir::new(lolcate_config_path())
        .min_depth(1)
        .into_iter();

    println!("{}", "Config file:".cyan());
    println!("  {}\n", global_config_fn().display().to_string().green());

    for entry in walker.filter_entry(|e| e.file_type().is_dir()) {
        if let Some(db_name) = entry.unwrap().file_name().to_str() {
            let config_fn = config_fn(db_name);
            let config = get_db_config(&config_fn);
            let description = config.description;
            let mut db_fn = lolcate_data_path();
            db_fn.push(db_name);
            db_data.push((
                db_name.to_string(),
                description.to_string(),
                config_fn.display().to_string(),
                ignores_fn(db_name).display().to_string(),
                db_fn.display().to_string(),
            ));
        }
    }

    match db_data.len() {
        0 => {
            println!("{}", "No databases found".cyan());
        }
        _ => {
            println!("{}", "Databases:".cyan());
            for (name, desc, config, ignores, db_fn) in db_data {
                println!("  {}", name.green());
                println!("    {}:  {}", "Description".magenta(), desc);
                println!("    {}:  {}", "Config file".magenta(), config);
                println!("    {}:  {}", "Ignores file".magenta(), ignores);
                println!("    {}:  {}", "Data file".magenta(), db_fn);
            }
        }
    };

    let tm = get_types_map();

    println!();

    match tm.len() {
        0 => {
            println!("{}", "No file types found".cyan());
        }
        _ => {
            println!("{}", "File types:".cyan());
            for (name, glob) in tm {
                print!("  {}", name.green());
                println!(": {}", glob.green());
            }
        }
    };
    println!();
    Ok(())
}

pub fn walker(config: &Config, database: &str) -> ignore::WalkParallel {
    let paths = &config.dirs;

    let mut wd = ignore::WalkBuilder::new(&paths[0]);

    wd.hidden(config.ignore_hidden) // Whether to ignore hidden files
        .parents(false) // Don't read ignore files from parent directories
        .follow_links(true) // Follow symbolic links
        .ignore(true) // Don't read .ignore files
        .git_global(config.gitignore) // Don't read global gitignore file
        .git_ignore(config.gitignore) // Don't read .gitignore files
        .git_exclude(false); // Don't read .git/info/exclude files

    for path in &paths[1..] {
        if !path.exists() && !config.ignore_missing {
            wd.add(path);
        }
    }

    wd.add_ignore(ignores_fn(database));
    wd.threads(num_cpus::get());
    wd.build_parallel()
}

fn update_databases(databases: Vec<String>) -> io::Result<()> {
    for db in databases {
        update_database(&db)?;
    }
    Ok(())
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
    let config = get_db_config(&config_fn);
    check_db_config(&config, &config_fn);

    let db_path = db_fn(db_name);
    let parent_path = db_path.parent().unwrap();
    if !parent_path.exists() {
        fs::create_dir_all(parent_path)?;
    }
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

    walker(&config, db_name).run(|| {
        let tx = tx.clone();
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

            // Ignore CACHEDIR.tag files.
            if cachedir::is_tagged(entry.path()).unwrap() {
                return ignore::WalkState::Continue;
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
    static UPPER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[[:upper:]]").unwrap());

    match RegexBuilder::new(&pattern)
        .case_insensitive(ignore_case || !UPPER_RE.is_match(&pattern))
        .build()
    {
        Ok(re) => re,
        Err(error) => {
            print_err!("invalid regex: {}", error);
            process::exit(1);
        }
    }
}

#[allow(unused)]
fn lookup_database(
    db_name: &str,
    patterns_re: &[Regex],
    types_re: &[Regex],
    mime: &MimeChoices,
) -> std::io::Result<()> {
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

    let color_output = atty::is(atty::Stream::Stdout);
    let input_file = fs::File::open(db_file)?;
    let decoder = lz4::Decoder::new(input_file)?;
    let mut reader = io::BufReader::new(decoder);

    let stdout = io::stdout();
    let lock = stdout.lock();
    let mut w = io::BufWriter::new(lock); // DEFAULT_BUF_SIZE: usize = 8 * 1024;

    // This is a pretty dirty way of filtering files
    // Hoping the user does not have a path containing this name
    let mime_map = vec![
        (
            Regex::new(r"(d|dir)").unwrap(),
            Regex::new(r",,,directory").unwrap(),
        ),
        (
            Regex::new(r"(f|file)").unwrap(),
            Regex::new(r",,,regular file").unwrap(),
        ),
    ];

    reader.for_byte_line(|_line| {
        let line = str::from_utf8(_line).unwrap();

        if mime != &MimeChoices::Any {
            #[allow(clippy::if_same_then_else)]
            if mime_map[0].0.is_match(format!("{:?}", mime).as_str())
                && !mime_map[0].1.is_match(line)
            {
                return Ok(true);
            } else if mime_map[1].0.is_match(format!("{:?}", mime).as_str())
                && !mime_map[1].1.is_match(line)
            {
                return Ok(true);
            }
        }

        if !types_re.is_empty() && !types_re.iter().any(|re| re.is_match(line)) {
            return Ok(true);
        }

        if !patterns_re.iter().all(|re| re.is_match(line)) {
            return Ok(true);
        }

        {
            let _ = w.write_all(
                fmt_output(line.split(",,,").collect::<Vec<_>>()[0], color_output).as_bytes(),
            );
            let _ = w.write_all(b"\n");
        }
        Ok(true)
    })
}

fn fmt_output<P: AsRef<Path>>(path: P, color_output: bool) -> String {
    let lscolors = LsColors::from_env().unwrap_or_default();

    if color_output {
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
    } else {
        path.as_ref().display().to_string()
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    create_global_config_if_needed()?;

    let database = args.database;
    let databases: Vec<String> = match args.all {
        true => database_names(lolcate_config_path()),
        false => vec![database.to_string()],
    };

    if args.create {
        create_database(&database)?;
        process::exit(0);
    }

    if args.update {
        update_databases(databases)?;
        process::exit(0);
    }

    if args.info {
        info_databases()?;
        process::exit(0);
    }

    // lookup
    let types_map = get_types_map();
    let types_re = args
        .types
        .unwrap_or_default()
        .split(',')
        .filter_map(|n| types_map.get(n))
        .map(|t| Regex::new(t).unwrap())
        .collect::<Vec<_>>();

    let ignore_case = args.ignore_case;

    let mime = args.mime.unwrap_or_default();

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
        lookup_database(&db_name, chained, &types_re, &mime)?;
    }

    Ok(())
}
