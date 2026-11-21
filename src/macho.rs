use std::ops::Range;

use anyhow::{Result, anyhow};
use apple_codesign::{MachOSigner, SettingsScope, SigningSettings};
use object::{Endianness, macho, read::macho::LoadCommandVariant};

pub mod exceptions;
pub mod functions;
pub mod jump_tables;
pub mod layout;
mod metadata;
mod sections;
pub mod strings;
pub mod unwind;

pub fn data_in_code(file: &object::File) -> Result<Vec<Range<u64>>> {
    let object::File::MachO64(macho) = file else { return Ok(Vec::new()) };
    let endian = macho.endian();
    let mut ranges = Vec::new();
    let mut commands = macho.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        let LoadCommandVariant::LinkeditData(linkedit) = command.variant()? else { continue };
        if linkedit.cmd.get(endian) != macho::LC_DATA_IN_CODE {
            continue;
        }
        let bytes = linkedit.data(endian, macho.data())?;
        let entries =
            object::pod::slice_from_all_bytes::<macho::DataInCodeEntry<Endianness>>(bytes)
                .map_err(|_| anyhow!("malformed LC_DATA_IN_CODE"))?;
        for entry in entries {
            let offset = entry.offset.get(endian) as u64;
            ranges.push(offset..offset + entry.length.get(endian) as u64);
        }
    }
    Ok(ranges)
}

const IDENTIFIER: &str = "i.wanna.see.how.you.lose.control";

pub fn adhoc_sign(macho: &[u8]) -> Result<Vec<u8>> {
    let mut settings = SigningSettings::default();
    settings.set_binary_identifier(SettingsScope::Main, IDENTIFIER);
    let mut signed = Vec::new();
    MachOSigner::new(macho)?.write_signed_binary(&settings, &mut signed)?;
    Ok(signed)
}
