// This file is part of Lolcate.
//
// Copyright © 2019 Nicolas Girard
//
// Lolcate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Lolcate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Lolcate.  If not, see <http://www.gnu.org/licenses/>.

use clap::{self, crate_version, App, AppSettings, Arg}; // SubCommand

pub(crate) fn build_cli() -> App<'static, 'static> {
    App::new("Lolcate")
        .version(crate_version!())
        .author("Nicolas Girard <girard.nicolas@gmail.com>")
        .about("Find files by name -- A better locate / mlocate / updatedb")
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::ColorAuto)
        .arg(
            Arg::with_name("create")
                .help("Create a database")
                .long("create")
                .takes_value(false)
                .conflicts_with_all(&["pattern", "update", "info"])
                .required(false),
        )
        .arg(
            Arg::with_name("info")
                .help("Display configuration informations and existing databases")
                .long("info")
                .takes_value(false)
                .conflicts_with_all(&["pattern", "update", "create", "database"])
                .required(false),
        )
        .arg(
            Arg::with_name("update")
                .help("Update database")
                .long("update")
                .short("u")
                .takes_value(false)
                .conflicts_with_all(&["pattern", "create", "info"])
                .required(false),
        )
        .arg(
            Arg::with_name("database")
                .help("Database to be used / created")
                .long("db")
                .takes_value(true)
                .required(false)
                .default_value("default"),
        )
        .arg(
            Arg::with_name("type")
                .help("One or several file types to search, separated with commas")
                .long("type")
                .short("t")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("mime")
                .help("Filter based on file type")
                .long("mime")
                .short("m")
                .takes_value(true)
                .required(false)
                .possible_values(&["f", "file", "d", "dir"]),
        )
        .arg(
            Arg::with_name("all")
                .help("Query / update all databases")
                .long("all")
                .takes_value(false)
                .conflicts_with_all(&["create", "info"])
                .required(false),
        )
        .arg(
            Arg::with_name("ignore_case")
                .help("Search case-insensitively [default: smart-case]")
                .long_help(
                    "Search the given patterns case-insensitively. Default is \"smart-case\", \
                     i.e. patterns are searched case-insensitively when all in lowercase, and \
                     sensitively otherwise.",
                )
                .short("i")
                .long("ignore-case")
                .takes_value(false)
                .required(false)
                .conflicts_with_all(&["create", "info", "update"]),
        )
        .arg(
            Arg::with_name("basename_pattern")
                .help("Match only basename against PATTERN")
                .long_help(
                    "Match only the basename against the specified PATTERN. Can be supplied \
                     multiple times, e.g. -b PATTERN1 -b PATTERN2",
                )
                .short("b")
                .long("basename")
                .takes_value(true)
                .value_name("patt")
                .number_of_values(1)
                .required(false)
                .conflicts_with_all(&["create", "info", "update"]),
        )
        .arg(
            Arg::with_name("color")
                .help("When to colorize output during search")
                .long("color")
                .short("c")
                .takes_value(true)
                .possible_values(&["always", "auto", "never"])
                .value_name("when")
                .required(false)
                .conflicts_with_all(&["create", "info", "update"]),
        )
        .arg(
            Arg::with_name("ansi")
                .help("True Color to colorize output")
                .long("ansi")
                .short("a")
                .takes_value(true)
                .value_name("hex")
                .required(false)
                .conflicts_with_all(&["create", "info", "update"])
                // .validator(
                //     |t| {
                //         t.parse::<u8>()
                //             .map_err(|_t| "must be below 255")
                //             .map(|_t| ())
                //             .map_err(|e| e.to_string())
                //     },
                // ),
        )
        .arg(
            Arg::with_name("pattern")
                .value_name("PATTERN")
                .min_values(1)
                .required(false),
        )
}
