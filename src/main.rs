mod cli;
mod config;
mod logging;
mod macho;
mod passes;
mod rewrite;

use std::fs;

use anyhow::{Context, Result};
use clap::Parser;
use object::BinaryFormat;

fn main() {
    logging::init();
    if let Err(error) = run() {
        log::error!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = cli::Args::parse();
    if args.init {
        return config::init();
    }

    let mut config = match &args.config {
        Some(path) => config::Config::load(path)?,
        None => config::Config::load_default()?,
    };
    if let Some(input) = args.input {
        config.input = Some(input);
    }
    if let Some(output) = args.output {
        config.output = Some(output);
    }
    let dump = args.dump || config.dump;
    let banner = config.banner_lines()?;
    let input = config
        .input
        .clone()
        .context("no input: set `input` in scene.toml or pass it on the command line")?;
    let output = config
        .output
        .clone()
        .context("no output: set `output` in scene.toml or pass it on the command line")?;

    let data = fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
    let file =
        object::File::parse(&*data).context("parsing binary (fat mach-o? thin it with lipo)")?;
    log::info!("loaded {} ({} bytes)", input.display(), data.len());

    let mut out = rewrite::rewrite(
        &file,
        &data,
        dump,
        &config.passes,
        &banner,
        config.banner_into.as_deref(),
    )?;
    if file.format() == BinaryFormat::MachO {
        out = macho::adhoc_sign(&out)?;
    }

    fs::write(&output, &out).with_context(|| format!("writing {}", output.display()))?;
    fs::set_permissions(&output, fs::metadata(&input)?.permissions())?;
    log::info!(target: "scene::done", "wrote {} ({} bytes)", output.display(), out.len());
    Ok(())
}
