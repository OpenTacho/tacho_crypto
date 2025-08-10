use crate::session::session_key::TachoSessionKey;
use aes::{Aes128, Aes192, Aes256, cipher::inout::InOutBuf};
use cbc::{Decryptor, Encryptor};
use cipher::BlockCipherDecrypt;
use cipher::BlockCipherEncrypt;
use cipher::BlockModeDecrypt;
use cipher::BlockModeEncrypt;
use cipher::block_padding::{Iso7816, UnpadError};
use cipher::consts::U16;
use cipher::inout::PadError;
use cipher::{Array, KeyInit};

type AesBlock = Array<u8, U16>;

/// AES-128, AES-192 or AES-256
pub enum TachoAes {
    CS1(Aes128),
    CS2(Aes192),
    CS3(Aes256),
}

impl TachoAes {
    pub fn new(k_enc: &TachoSessionKey) -> Self {
        match k_enc {
            TachoSessionKey::CS1(k_enc) => {
                // 16-byte K_ENC
                Self::CS1(Aes128::new(&k_enc.0.into()))
            }
            TachoSessionKey::CS2(k_enc) => {
                // 24-byte K_ENC
                Self::CS2(Aes192::new(&k_enc.0.into()))
            }
            TachoSessionKey::CS3(k_enc) => {
                // 32-byte K_ENC
                Self::CS3(Aes256::new(&k_enc.0.into()))
            }
        }
    }

    /// Encrypts one block in place.
    pub fn encrypt_block_mut(&mut self, block: &mut AesBlock) {
        match self {
            Self::CS1(aes128) => aes128.encrypt_block(block),
            Self::CS2(aes192) => aes192.encrypt_block(block),
            Self::CS3(aes256) => aes256.encrypt_block(block),
        }
    }

    /// Decrypts one block in place.
    pub fn decrypt_block_mut(&mut self, block: &mut AesBlock) {
        match self {
            Self::CS1(aes128) => aes128.decrypt_block(block),
            Self::CS2(aes192) => aes192.decrypt_block(block),
            Self::CS3(aes256) => aes256.decrypt_block(block),
        }
    }
}

/// CBC Encryptor for AES-128, AES-192 or AES-256
pub enum TachoAesCbcEnc {
    CS1(cbc::Encryptor<Aes128>),
    CS2(cbc::Encryptor<Aes192>),
    CS3(cbc::Encryptor<Aes256>),
}

impl TachoAesCbcEnc {
    pub fn new(k_enc: &TachoSessionKey, iv: [u8; 16]) -> Self {
        use aes::cipher::KeyIvInit;
        match k_enc {
            TachoSessionKey::CS1(k_enc) => {
                // 16-byte K_ENC
                Self::CS1(Encryptor::<Aes128>::new(&k_enc.0.into(), &iv.into()))
            }
            TachoSessionKey::CS2(k_enc) => {
                // 24-byte K_ENC
                Self::CS2(Encryptor::<Aes192>::new(&k_enc.0.into(), &iv.into()))
            }
            TachoSessionKey::CS3(k_enc) => {
                // 32-byte K_ENC
                Self::CS3(Encryptor::<Aes256>::new(&k_enc.0.into(), &iv.into()))
            }
        }
    }

    /// Encrypts blocks in place, without padding.
    pub fn encrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, '_, AesBlock>) {
        match self {
            Self::CS1(aes128) => aes128.encrypt_blocks_inout(blocks),
            Self::CS2(aes192) => aes192.encrypt_blocks_inout(blocks),
            Self::CS3(aes256) => aes256.encrypt_blocks_inout(blocks),
        }
    }

    /// Encrypts one block in place.
    pub fn encrypt_block_mut(&mut self, block: &mut AesBlock) {
        match self {
            Self::CS1(aes128) => aes128.encrypt_block(block),
            Self::CS2(aes192) => aes192.encrypt_block(block),
            Self::CS3(aes256) => aes256.encrypt_block(block),
        }
    }

    /// Encrypts with Iso7816 `80 00 .. 00` padding, in-place.
    ///
    /// Errors: when size of output buffer is insufficient.
    pub fn encrypt_padded_mut(self, buf: &mut [u8], msg_len: usize) -> Result<&[u8], PadError> {
        match self {
            Self::CS1(aes128) => aes128.encrypt_padded::<Iso7816>(buf, msg_len),
            Self::CS2(aes192) => aes192.encrypt_padded::<Iso7816>(buf, msg_len),
            Self::CS3(aes256) => aes256.encrypt_padded::<Iso7816>(buf, msg_len),
        }
    }
}

/// CBC Decryptor for AES-128, AES-192 or AES-256
pub enum TachoAesCbcDec {
    CS1(cbc::Decryptor<Aes128>),
    CS2(cbc::Decryptor<Aes192>),
    CS3(cbc::Decryptor<Aes256>),
}

impl TachoAesCbcDec {
    pub fn new(k_enc: &TachoSessionKey, iv: [u8; 16]) -> Self {
        use aes::cipher::KeyIvInit;
        match k_enc {
            TachoSessionKey::CS1(k_enc) => {
                // 16-byte K_ENC
                Self::CS1(Decryptor::<Aes128>::new(&k_enc.0.into(), &iv.into()))
            }
            TachoSessionKey::CS2(k_enc) => {
                // 24-byte K_ENC
                Self::CS2(Decryptor::<Aes192>::new(&k_enc.0.into(), &iv.into()))
            }
            TachoSessionKey::CS3(k_enc) => {
                // 32-byte K_ENC
                Self::CS3(Decryptor::<Aes256>::new(&k_enc.0.into(), &iv.into()))
            }
        }
    }

    /// Encrypts one block in place.
    pub fn decrypt_block_mut(&mut self, block: &mut AesBlock) {
        match self {
            Self::CS1(aes128) => aes128.decrypt_block(block),
            Self::CS2(aes192) => aes192.decrypt_block(block),
            Self::CS3(aes256) => aes256.decrypt_block(block),
        }
    }

    /// Encrypts blocks in place, without padding.
    pub fn decrypt_blocks_inout_mut(&mut self, blocks: InOutBuf<'_, '_, AesBlock>) {
        match self {
            Self::CS1(aes128) => aes128.decrypt_blocks_inout(blocks),
            Self::CS2(aes192) => aes192.decrypt_blocks_inout(blocks),
            Self::CS3(aes256) => aes256.decrypt_blocks_inout(blocks),
        }
    }

    /// Decrypts with Iso7816 `80 00 .. 00` padding, in-place.
    ///
    /// Errors: On failed unpadding operation error.
    pub fn decrypt_padded_mut(self, buf: &mut [u8]) -> Result<&[u8], UnpadError> {
        match self {
            Self::CS1(aes128) => aes128.decrypt_padded::<Iso7816>(buf),
            Self::CS2(aes192) => aes192.decrypt_padded::<Iso7816>(buf),
            Self::CS3(aes256) => aes256.decrypt_padded::<Iso7816>(buf),
        }
    }
}
