use u64x2::{u64x2, xor};
use intr;

mod expand;

/// AES-192 block cipher
#[derive(Copy, Clone)]
pub struct Aes192 {
    encrypt_keys: [u64x2; 13],
    decrypt_keys: [u64x2; 13],
}

impl Aes192 {
    /// Create new AES-192 instance with given key
    #[inline]
    pub(crate) fn init(key: &[u8; 24]) -> Self {
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Aes192 { encrypt_keys, decrypt_keys }
    }

    /// Encrypt in-place one 128 bit block
    #[inline]
    pub(crate) fn encrypt(&self, block: &mut [u8; 16]) {
        let mut data = u64x2::read(block);
        self.encrypt_u64x2(&mut data);
        data.write(block);
    }

    /// Decrypt in-place one 128 bit block
    #[inline]
    pub(crate) fn decrypt(&self, block: &mut [u8; 16]) {
        let keys = self.decrypt_keys;
        let mut d = u64x2::read(block);
        unsafe {
            d = xor(d, keys[12]);
            d = intr::aesni_aesdec(d, keys[11]);
            d = intr::aesni_aesdec(d, keys[10]);
            d = intr::aesni_aesdec(d, keys[9]);
            d = intr::aesni_aesdec(d, keys[8]);
            d = intr::aesni_aesdec(d, keys[7]);
            d = intr::aesni_aesdec(d, keys[6]);
            d = intr::aesni_aesdec(d, keys[5]);
            d = intr::aesni_aesdec(d, keys[4]);
            d = intr::aesni_aesdec(d, keys[3]);
            d = intr::aesni_aesdec(d, keys[2]);
            d = intr::aesni_aesdec(d, keys[1]);
            d = intr::aesni_aesdeclast(d, keys[0]);
        }
        d.write(block);
    }

    /// Encrypt in-place eight 128 bit blocks (1024 bits in total) using
    /// instruction-level parallelism
    #[inline]
    pub(crate) fn encrypt8(&self, blocks: &mut [u8; 8*16]) {
        let mut data = u64x2::read8(blocks);
        self.encrypt_u64x2_8(&mut data);
        u64x2::write8(data, blocks);
    }

    /// Decrypt in-place eight 128 bit blocks (1024 bits in total) using
    /// instruction-level parallelism
    #[inline]
    pub(crate) fn decrypt8(&self, blocks: &mut [u8; 8*16]) {
        let keys = self.decrypt_keys;
        let mut data = u64x2::read8(blocks);
        unsafe {
            round8!(xor, data, keys[12]);
            round8!(intr::aesni_aesdec, data, keys[11]);
            round8!(intr::aesni_aesdec, data, keys[10]);
            round8!(intr::aesni_aesdec, data, keys[9]);
            round8!(intr::aesni_aesdec, data, keys[8]);
            round8!(intr::aesni_aesdec, data, keys[7]);
            round8!(intr::aesni_aesdec, data, keys[6]);
            round8!(intr::aesni_aesdec, data, keys[5]);
            round8!(intr::aesni_aesdec, data, keys[4]);
            round8!(intr::aesni_aesdec, data, keys[3]);
            round8!(intr::aesni_aesdec, data, keys[2]);
            round8!(intr::aesni_aesdec, data, keys[1]);
            round8!(intr::aesni_aesdeclast, data, keys[0]);
        }
        u64x2::write8(data, blocks);
    }

    #[inline(always)]
    pub(crate) fn encrypt_u64x2(&self, data: &mut u64x2) {
        let keys = self.encrypt_keys;
        let mut d = *data;
        unsafe {
            d = xor(d, keys[0]);
            d = intr::aesni_aesenc(d, keys[1]);
            d = intr::aesni_aesenc(d, keys[2]);
            d = intr::aesni_aesenc(d, keys[3]);
            d = intr::aesni_aesenc(d, keys[4]);
            d = intr::aesni_aesenc(d, keys[5]);
            d = intr::aesni_aesenc(d, keys[6]);
            d = intr::aesni_aesenc(d, keys[7]);
            d = intr::aesni_aesenc(d, keys[8]);
            d = intr::aesni_aesenc(d, keys[9]);
            d = intr::aesni_aesenc(d, keys[10]);
            d = intr::aesni_aesenc(d, keys[11]);
            d = intr::aesni_aesenclast(d, keys[12]);
        }
        *data = d;
    }

    #[inline(always)]
    pub(crate) fn encrypt_u64x2_8(&self, data: &mut [u64x2; 8]) {
        let keys = self.encrypt_keys;
        unsafe {
            round8!(xor, data, keys[0]);
            round8!(intr::aesni_aesenc, data, keys[1]);
            round8!(intr::aesni_aesenc, data, keys[2]);
            round8!(intr::aesni_aesenc, data, keys[3]);
            round8!(intr::aesni_aesenc, data, keys[4]);
            round8!(intr::aesni_aesenc, data, keys[5]);
            round8!(intr::aesni_aesenc, data, keys[6]);
            round8!(intr::aesni_aesenc, data, keys[7]);
            round8!(intr::aesni_aesenc, data, keys[8]);
            round8!(intr::aesni_aesenc, data, keys[9]);
            round8!(intr::aesni_aesenc, data, keys[10]);
            round8!(intr::aesni_aesenc, data, keys[11]);
            round8!(intr::aesni_aesenclast, data, keys[12]);
        }
    }
}

#[cfg(test)]
mod test_expand;
