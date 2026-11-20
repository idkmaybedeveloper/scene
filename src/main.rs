mod cli;
mod macho;
mod passes;
mod rewrite;

use std::fs;

use anyhow::{Context, Result};
use clap::Parser;
use object::BinaryFormat;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    let data =
        fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;
    let file =
        object::File::parse(&*data).context("parsing binary (fat mach-o? thin it with lipo)")?;

    let mut out = rewrite::rewrite(&file, &data, args.dump)?;
    if file.format() == BinaryFormat::MachO {
        out = macho::adhoc_sign(&out)?;
    }

    fs::write(&args.output, &out).with_context(|| format!("writing {}", args.output.display()))?;
    fs::set_permissions(&args.output, fs::metadata(&args.input)?.permissions())?;
    Ok(())
}
