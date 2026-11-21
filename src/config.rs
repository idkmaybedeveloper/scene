use std::{fmt, fs, path::Path, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};

const DEFAULT_PATH: &str = "scene.toml";
const DEFAULT_SEED: u32 = 0x7363_656e; // "scen"

/// intensity of a pass: 0 = off, 1 = default, higher = stronger. accepts either an
/// integer or a boolean (true -> 1, false -> 0) in the config for convenience
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Level(pub u32);

impl Level {
    pub fn get(self) -> u32 {
        self.0
    }

    pub fn on(self) -> bool {
        self.0 > 0
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Level;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a boolean or a non-negative integer level")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Level, E> {
                Ok(Level(value as u32))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Level, E> {
                u32::try_from(value).map(Level).map_err(|_| E::custom("level is too large"))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Level, E> {
                u32::try_from(value).map(Level).map_err(|_| E::custom("level must fit in u32"))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Passes {
    pub cff: Level,
    pub mba: Level,
    pub strings: bool,
    pub seed: u32,
}

impl Default for Passes {
    fn default() -> Self {
        Self { cff: Level(1), mba: Level(1), strings: true, seed: DEFAULT_SEED }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub dump: bool,
    pub banner: Option<PathBuf>,
    pub banner_into: Option<String>,
    pub passes: Passes,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    pub fn banner_lines(&self) -> Result<Vec<Vec<u8>>> {
        let Some(path) = &self.banner else { return Ok(Vec::new()) };
        let text = fs::read(path).with_context(|| format!("reading banner {}", path.display()))?;
        Ok(text
            .split(|&b| b == b'\n')
            .map(|line| line.iter().copied().filter(|&b| b != 0 && b != b'\r').collect::<Vec<u8>>())
            .collect())
    }

    /// loads ./scene.toml when present, otherwise an empty default config so that
    /// input/output can still come from the command line
    pub fn load_default() -> Result<Self> {
        let path = Path::new(DEFAULT_PATH);
        if path.exists() { Self::load(path) } else { Ok(Self::default()) }
    }
}

const TEMPLATE: &str = "\
# scene obfuscation config. run `scene` in this directory to apply it.

input = \"path/to/binary\"
output = \"path/to/binary.obf\"
dump = false
# banner = \"notes.txt\"
# banner_into = \"JNI_OnLoad\"

[passes]
cff = 1         # control-flow flattening: 0 = off, 1 = default, higher = more states
mba = 1         # mixed boolean-arithmetic: 0 = off, 1 = default, higher = deeper nesting
strings = true  # string + constant encryption
seed = 0x7363656e
";

pub fn init() -> Result<()> {
    let path = Path::new(DEFAULT_PATH);
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    fs::write(path, TEMPLATE).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("wrote {}", path.display());
    Ok(())
}
