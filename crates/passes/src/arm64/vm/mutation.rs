use anyhow::{Result, anyhow};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};

#[derive(Clone)]
pub struct Registers {
    pub pc: u8,
    pub opcode: u8,
    pub dst: u8,
    pub lhs: u8,
    pub rhs: u8,
    pub aux: u8,
    pub immediate: u8,
    pub base: u8,
    pub scratch: u8,
}

pub struct Mutation {
    pub seed: u64,
    pub rng: StdRng,
    pub registers: Registers,
    pub slots: [u8; 32],
    pub save_order: Vec<u8>,
    pub fields: [u32; 4],
    pub header: u32,
    pub immediate: u32,
}

impl Mutation {
    pub fn new(seed: u32, mutation_seed: Option<u64>) -> Result<Self> {
        let seed = match mutation_seed {
            Some(seed) => seed,
            None => {
                let mut entropy = [0; 8];
                getrandom::getrandom(&mut entropy)
                    .map_err(|error| anyhow!("vm mutation entropy: {error}"))?;
                u64::from(seed) ^ u64::from_le_bytes(entropy)
            }
        };
        let mut rng = StdRng::seed_from_u64(seed);
        let mut registers: Vec<u8> = (9..=17).collect();
        registers.shuffle(&mut rng);
        let mut slots = std::array::from_fn(|i| i as u8);
        slots.shuffle(&mut rng);
        let mut save_order: Vec<u8> = (0..31).collect();
        save_order.shuffle(&mut rng);
        let mut fields = [0, 1, 2, 3];
        fields.shuffle(&mut rng);
        let header = if rng.gen_bool(0.5) { 0 } else { 8 };
        Ok(Self {
            seed,
            registers: Registers {
                pc: registers[0],
                opcode: registers[1],
                dst: registers[2],
                lhs: registers[3],
                rhs: registers[4],
                aux: registers[5],
                immediate: registers[6],
                base: registers[7],
                scratch: registers[8],
            },
            slots,
            save_order,
            fields,
            header,
            immediate: 8 - header,
            rng,
        })
    }

    pub fn zero_offset(&self) -> u32 {
        u32::from(self.slots[31]) * 8
    }

    pub fn slot(&self, register: u8) -> u8 {
        if register == 32 { 32 } else { self.slots[register as usize] }
    }
}
