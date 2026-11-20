use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, about = "meowmeomwomemwoemwoemwo")]
pub struct Args {
    /// binary to rewrite
    pub input: PathBuf,
    /// where to write binary
    pub output: PathBuf,

    /// print the disassembly of every code section
    #[arg(short, long)]
    pub dump: bool,
}
