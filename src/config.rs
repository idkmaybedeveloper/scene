use std::{fs, path::Path, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_PATH: &str = "scene.toml";
const DEFAULT_SEED: u32 = 0x7363_656e; // "scen"

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Passes {
    pub cff: bool,
    pub mba: bool,
    pub strings: bool,
    pub seed: u32,
}

impl Default for Passes {
    fn default() -> Self {
        Self { cff: true, mba: true, strings: true, seed: DEFAULT_SEED }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub dump: bool,
    pub passes: Passes,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
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

[passes]
cff = true      # control-flow flattening
mba = true      # mixed boolean-arithmetic substitution
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
