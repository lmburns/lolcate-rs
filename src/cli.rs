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
use clap::{Parser, ValueEnum};

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
#[command(author = "Nicolas Girard <girard.nicolas@gmail.com>")]
#[command(version = "0.1")]
// #[arg(setting = clap::AppSettings::ColoredHelp, setting = clap::AppSettings::ColorAuto)]
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
