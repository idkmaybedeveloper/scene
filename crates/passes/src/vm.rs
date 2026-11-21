use std::ops::Range;

use anyhow::{Context, Result};
use rand::Rng;

pub struct Anchor {
    pub address: u64,
    pub(crate) salt: u64,
    pub(crate) rotation: u32,
}

pub struct Binding {
    pub anchors: Vec<Anchor>,
    pub keys: Range<usize>,
    pub(crate) tables: Vec<Range<usize>>,
}

impl Binding {
    pub fn seal(self, code: &mut [u8], mut read: impl FnMut(u64) -> Result<u32>) -> Result<()> {
        let mut hash = 0u64;
        for anchor in self.anchors {
            hash = (hash ^ u64::from(read(anchor.address)?))
                .rotate_right(anchor.rotation)
                .wrapping_add(anchor.salt);
        }
        let keys = code.get_mut(self.keys).context("vm: key data outside output")?;
        for pair in keys.as_chunks_mut::<32>().0 {
            for (index, byte) in pair[16..].iter_mut().enumerate() {
                *byte ^= hash.to_le_bytes()[index % 8];
            }
        }
        for range in self.tables {
            for word in
                code.get_mut(range).context("vm: table outside output")?.as_chunks_mut::<8>().0
            {
                for (byte, mask) in word.iter_mut().zip(hash.to_le_bytes()) {
                    *byte ^= mask;
                }
            }
        }
        Ok(())
    }
}

pub struct Records {
    pub offsets: Vec<usize>,
}

impl Records {
    pub fn new(count: usize, minimum: usize, rng: &mut impl Rng) -> Self {
        let mut offsets = vec![0];
        for _ in 0..count {
            offsets.push(offsets.last().unwrap() + minimum + rng.gen_range(0..4) * 16);
        }
        Self { offsets }
    }

    pub fn size(&self, index: usize) -> usize {
        self.offsets[index + 1] - self.offsets[index]
    }
    pub fn len(&self) -> usize {
        *self.offsets.last().unwrap()
    }
}
