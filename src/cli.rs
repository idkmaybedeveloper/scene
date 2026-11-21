use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, about = "meowmeomwomemwoemwoemwo")]
pub struct Args {
    /// binary to rewrite (overrides `input` from the config)
    pub input: Option<PathBuf>,
    /// where to write binary (overrides `output` from the config)
    pub output: Option<PathBuf>,

    /// config file to read (default: ./scene.toml when present)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// write a default scene.toml and exit
    #[arg(long)]
    pub init: bool,

    /// print the disassembly of every code section
    #[arg(short, long)]
    pub dump: bool,
}
