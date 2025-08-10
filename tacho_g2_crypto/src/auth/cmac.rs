use aes::{Aes128, Aes192, Aes256};
use cipher::{block_padding::Block, consts::U16};

use crate::{
    auth::auth_token::{AuthTokenFromCmac, Cs1AuthToken, Cs2AuthToken, Cs3AuthToken},
    session::session_key::TachoSessionKey,
};

use super::auth_token::TachoAuthenticationToken;
use cmac::{Cmac, KeyInit, Mac};
use der::Writer;

/// Tacho CMAC instance. Aes128, Aes192 or Aes256.
pub enum TachoCmac {
    CS1(Cmac<Aes128>),
    CS2(Cmac<Aes192>),
    CS3(Cmac<Aes256>),
}

impl TachoCmac {
    /// Constructs new CMAC
    pub fn from_key(key: &TachoSessionKey) -> Self {
        match key {
            TachoSessionKey::CS1(k_mac) => {
                // 16-byte K_MAC
                TachoCmac::CS1(Cmac::<Aes128>::new(&k_mac.0.into()))
            }
            TachoSessionKey::CS2(k_mac) => {
                // 24-byte K_MAC
                TachoCmac::CS2(Cmac::<Aes192>::new(&k_mac.0.into()))
            }
            TachoSessionKey::CS3(k_mac) => {
                // 32-byte K_MAC
                TachoCmac::CS3(Cmac::<Aes256>::new(&k_mac.0.into()))
            }
        }
    }
    /// Update state using the provided data.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            TachoCmac::CS1(cmac) => cmac.update(data),
            TachoCmac::CS2(cmac) => cmac.update(data),
            TachoCmac::CS3(cmac) => cmac.update(data),
        }
    }

    /// Update state using the provided data.
    pub fn update_der(&mut self, enc: &impl der::Encode) -> Result<u32, der::Error> {
        let len = enc.encoded_len()?;
        enc.encode(self)?;
        Ok(u32::from(len))
    }

    /// Update Cmac state using the provided data.
    /// Then pad up to 16 bytes (Iso7816 `80 00 .. 00`).
    pub fn update_der_padded(&mut self, enc: &impl der::Encode) -> Result<u32, der::Error> {
        let len = self.update_der(enc)?;

        let mut block = Block::<U16>::default();
        let padding = padding_gen::gen_iso7816_padding(len as usize, &mut block);
        self.update(padding);
        Ok(len)
    }

    /// Obtain the result of Cmac and consume [`TachoCmac`] instance.
    pub fn finalize(self) -> TachoAuthenticationToken {
        match self {
            TachoCmac::CS1(mac) => {
                // 16 bytes MAC
                let mac = mac.finalize().into_bytes();

                // cuts to 8 bytes
                Cs1AuthToken::cut_from_cmac(mac.as_slice())
                    .expect("t_picc to be at least 8 bytes")
                    .into()
            }
            TachoCmac::CS2(mac) => {
                // 24 bytes MAC
                let mac = mac.finalize().into_bytes();

                // cuts to 12 bytes
                Cs2AuthToken::cut_from_cmac(mac.as_slice())
                    .expect("t_picc to be at least 12 bytes")
                    .into()
            }
            TachoCmac::CS3(mac) => {
                // 32 bytes MAC
                let mac = mac.finalize().into_bytes();

                // cuts to 16 bytes
                Cs3AuthToken::cut_from_cmac(mac.as_slice())
                    .expect("t_picc to be at least 16 bytes")
                    .into()
            }
        }
    }
}

impl Writer for TachoCmac {
    fn write(&mut self, slice: &[u8]) -> der::Result<()> {
        self.update(slice);
        Ok(())
    }
}

mod padding_gen {
    use cipher::block_padding::Padding;
    use cipher::{
        array::ArraySize,
        block_padding::{Block, Iso7816},
    };

    pub fn gen_iso7816_padding<B: ArraySize>(len: usize, block: &mut Block<B>) -> &[u8] {
        let block_pos = len % B::USIZE;
        Iso7816::pad(block, block_pos);
        &block[block_pos..]
    }

    #[test]
    pub fn padding_is_valid() {
        use cipher::consts::U16;
        use hex_literal::hex;

        let mut block = Block::<U16>::default();

        assert_eq!(hex!("80 00 00"), gen_iso7816_padding(13, &mut block));
        assert_eq!(hex!("80 00"), gen_iso7816_padding(14, &mut block));
        assert_eq!(hex!("80"), gen_iso7816_padding(15, &mut block));
        assert_eq!(
            hex!("80 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"),
            gen_iso7816_padding(16, &mut block)
        );
        assert_eq!(
            hex!("80 00 00 00  00 00 00 00  00 00 00 00  00 00 00"),
            gen_iso7816_padding(17, &mut block)
        );
        assert_eq!(hex!("80 00 00"), gen_iso7816_padding(29, &mut block));
        assert_eq!(hex!("80 00"), gen_iso7816_padding(30, &mut block));
        assert_eq!(hex!("80"), gen_iso7816_padding(31, &mut block));
    }
}
