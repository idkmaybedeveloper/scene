use aes::{
    Aes128, Block,
    cipher::{KeyIvInit, StreamCipher},
};
use anyhow::{Result, anyhow};

pub struct EncryptedString {
    pub ciphertext: Vec<u8>,
    pub keys: Vec<u8>,
    pub nonce: [u8; 32],
    pub seed: u32,
}

impl EncryptedString {
    pub fn new(plaintext: &[u8]) -> Result<Self> {
        let mut key = [0; 16];
        let mut nonce = [0; 16];
        random(&mut key)?;
        random(&mut nonce)?;
        let mut ciphertext = plaintext.to_vec();
        ctr::Ctr128BE::<Aes128>::new(&key.into(), &nonce.into()).apply_keystream(&mut ciphertext);
        let mut round_key = key;
        let mut keys = Vec::with_capacity(352);
        let mut rcon = 1u8;
        for round in 0..=10 {
            let mut mask = [0; 16];
            random(&mut mask)?;
            keys.extend_from_slice(&mask);
            keys.extend(round_key.iter().zip(mask).map(|(&a, b)| a ^ b));
            if round == 10 {
                break;
            }
            let word = [round_key[13], round_key[14], round_key[15], round_key[12]];
            let mut subword = Block::default();
            for column in subword.chunks_exact_mut(4) {
                column.copy_from_slice(&word);
            }
            // ref: https://doi.org/10.6028/NIST.FIPS.197-upd1
            aes::hazmat::cipher_round(&mut subword, &Block::default());
            aes::hazmat::inv_mix_columns(&mut subword);
            for i in 0..4 {
                round_key[i] ^= subword[i] ^ if i == 0 { rcon } else { 0 };
            }
            for i in 4..16 {
                round_key[i] ^= round_key[i - 4];
            }
            rcon = rcon.wrapping_shl(1) ^ if rcon & 0x80 != 0 { 0x1b } else { 0 };
        }
        let mut masked_nonce = [0; 32];
        random(&mut masked_nonce[..16])?;
        for i in 0..16 {
            masked_nonce[16 + i] = nonce[i] ^ masked_nonce[i];
        }
        let mut seed = [0; 4];
        random(&mut seed)?;
        Ok(Self { ciphertext, keys, nonce: masked_nonce, seed: u32::from_le_bytes(seed) })
    }
}

fn random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|e| anyhow!("generating string key: {e}"))
}
