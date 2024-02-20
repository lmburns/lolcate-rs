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

use serde::Deserialize;
use std::{collections::HashMap, fs, io::prelude::*, path, process};
use toml::de::Error;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub description: String,
    #[serde(deserialize_with = "deserialize::deserialize")]
    pub dirs: Vec<path::PathBuf>,
    #[serde(default)]
    pub skip: Skip,
    #[serde(default)]
    pub gitignore: bool,
    pub ignore_symlinks: bool,
    pub ignore_hidden: bool,
    pub ignore_missing: bool,
    pub color: Option<String>,
}

#[derive(Debug, Default, Deserialize, PartialEq, Copy, Clone)]
pub enum Skip {
    #[default]
    None,
    Dirs,
    Files,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GlobalConfig {
    pub(crate) types: HashMap<String, String>,
}

pub(crate) fn read_toml_file<P: ?Sized, T>(path: &P, buffer: &mut String) -> Result<T, Error>
where
    P: AsRef<path::Path>,
    T: serde::de::DeserializeOwned,
{
    let mut configuration_file: fs::File = match fs::OpenOptions::new().read(true).open(path) {
        Ok(val) => val,
        Err(_e) => {
            eprintln!("Cannot open file {}", path.as_ref().display());
            process::exit(1);
        },
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
