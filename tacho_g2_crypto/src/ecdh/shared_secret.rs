use crate::session::{kdf::kdf_enc_mac_sha2, session_key::TachoSessionKey};

use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use elliptic_curve::ecdh::SharedSecret;

/// Result of ECDH
pub enum TachoSharedSecret {
    /// Nist, len 32
    P256(p256::ecdh::SharedSecret),

    /// Nist, len 48
    P384(p384::ecdh::SharedSecret),

    /// Nist, len 66
    P521(p521::ecdh::SharedSecret),

    /// Brainpool
    BP256(SharedSecret<BrainpoolP256r1>),

    /// Brainpool
    BP384(SharedSecret<BrainpoolP384r1>),

    /// Brainpool
    BP512([u8; 64]),
}

impl TachoSharedSecret {
    // /// This value contains the raw serialized x-coordinate of the elliptic curve
    // /// point computed from a Diffie-Hellman exchange, serialized as bytes.
    // ///
    // ///
    // /// # ⚠️ WARNING: NOT UNIFORMLY RANDOM! ⚠️
    // ///
    // /// This value is not uniformly random and should not be used directly
    // /// as a cryptographic key for anything which requires that property
    // /// (e.g. symmetric ciphers).
    // ///
    // /// Instead, the resulting value should be used as input to a Key Derivation
    // /// Function (KDF) or cryptographic hash function to produce a symmetric key.
    // pub fn raw_secret_bytes(&self) -> Vec<u8> {
    //     match self {
    //         TachoSharedSecret::P256(shared_secret) => shared_secret.raw_secret_bytes().to_vec(),
    //         TachoSharedSecret::P384(shared_secret) => shared_secret.raw_secret_bytes().to_vec(),
    //         TachoSharedSecret::P521(shared_secret) => shared_secret.raw_secret_bytes().to_vec(),
    //         TachoSharedSecret::BP256(_) => todo!(),
    //         TachoSharedSecret::BP384(_) => todo!(),
    //         TachoSharedSecret::BP512(_) => todo!(),
    //     }
    // }

    /// Tachograph ECDH ECKA-EG KDF
    ///
    /// Computes K_MAC and K_ENC from K (self) and N_PICC
    ///
    /// returns (k_enc, k_mac)
    pub fn derive_key(&self, n_picc: [u8; 8]) -> (TachoSessionKey, TachoSessionKey) {
        // CSM_179
        // In steps 5 and 8 above, the card and the vehicle unit shall
        // use the key derivation function for AES session keys
        // defined in [TR-03111], with the following precisions and
        // changes:
        match self {
            TachoSharedSecret::P256(shared_secret) => kdf_enc_mac_sha2(shared_secret, n_picc),
            TachoSharedSecret::P384(shared_secret) => kdf_enc_mac_sha2(shared_secret, n_picc),
            TachoSharedSecret::P521(shared_secret) => kdf_enc_mac_sha2(shared_secret, n_picc),

            TachoSharedSecret::BP256(shared_secret) => kdf_enc_mac_sha2(shared_secret, n_picc),
            TachoSharedSecret::BP384(shared_secret) => kdf_enc_mac_sha2(shared_secret, n_picc),
            TachoSharedSecret::BP512(_shared_secret) => todo!("bp512"),
        }
    }
}
