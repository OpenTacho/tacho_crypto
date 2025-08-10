use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use cipher::BlockSizeUser;
use elliptic_curve::{Curve, ecdh::SharedSecret};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sha2::{
    Digest,
    digest::{FixedOutput, FixedOutputReset, Output},
};

use crate::{
    auth::auth_token::{AuthTokenFromCmac, Cs1AuthToken, Cs2AuthToken, Cs3AuthToken},
    session::session_key::{
        Cs1SessionKey, Cs2SessionKey, Cs3SessionKey, SessionKeyFromDigest, TachoSessionKey,
    },
};

/// TR-03111
///
/// Key Derivation Function for Session Keys.
///
/// example Digest: sha2::Sha256
pub fn kdf_tacho<D: Digest>(z_ab: &[u8], r: [u8; 8], counter: u32) -> Output<D> {
    let mut digest = D::new();

    // D = ZAB ‖ r ‖ counter
    digest.update(z_ab);
    digest.update(r);
    digest.update(counter.to_be_bytes());

    // KeyData = Hκ(D)
    digest.finalize()
}

pub trait TachoCurveDigest {
    /// Preferred digest to use when computing ECDSA signatures for this
    /// elliptic curve. This is typically a member of the SHA-2 family.
    type TachoDigest: BlockSizeUser + Digest + FixedOutput + FixedOutputReset;
}

// TODO: uncomment when Brainpools are ready
// impl<T> TachoCurveDigest for T
// where
//     T: DigestPrimitive,
// {
//     type TachoDigest = T::Digest;
// }

impl TachoCurveDigest for NistP256 {
    type TachoDigest = sha2::Sha256;
}
impl TachoCurveDigest for NistP384 {
    type TachoDigest = sha2::Sha384;
}
impl TachoCurveDigest for NistP521 {
    type TachoDigest = sha2::Sha512;
}

impl TachoCurveDigest for BrainpoolP256r1 {
    type TachoDigest = sha2::Sha256;
}
impl TachoCurveDigest for BrainpoolP384r1 {
    type TachoDigest = sha2::Sha384;
}

pub trait TachoCipherSuite {
    type SessionKey: SessionKeyFromDigest;
    type AuthToken: AuthTokenFromCmac;
}

impl TachoCipherSuite for NistP256 {
    type SessionKey = Cs1SessionKey;
    type AuthToken = Cs1AuthToken;
}

impl TachoCipherSuite for NistP384 {
    type SessionKey = Cs2SessionKey;
    type AuthToken = Cs2AuthToken;
}

impl TachoCipherSuite for NistP521 {
    type SessionKey = Cs3SessionKey;
    type AuthToken = Cs3AuthToken;
}

impl TachoCipherSuite for BrainpoolP256r1 {
    type SessionKey = Cs1SessionKey;
    type AuthToken = Cs1AuthToken;
}

impl TachoCipherSuite for BrainpoolP384r1 {
    type SessionKey = Cs2SessionKey;
    type AuthToken = Cs2AuthToken;
}

pub fn kdf_enc_mac_secret<C: Curve + TachoCurveDigest>(
    raw_k: &SharedSecret<C>,
    n_picc: [u8; 8],
) -> (Output<C::TachoDigest>, Output<C::TachoDigest>) {
    let raw_bytes = raw_k.raw_secret_bytes();
    let k_enc = kdf_tacho::<C::TachoDigest>(raw_bytes, n_picc, 1);
    let k_mac = kdf_tacho::<C::TachoDigest>(raw_bytes, n_picc, 2);
    (k_enc, k_mac)
}

pub fn kdf_enc_mac_sha2<C: Curve + TachoCurveDigest + TachoCipherSuite>(
    raw_k: &SharedSecret<C>,
    n_picc: [u8; 8],
) -> (TachoSessionKey, TachoSessionKey) {
    let (k_enc, k_mac) = kdf_enc_mac_secret(raw_k, n_picc);

    // cuts first bytes of k_enc, and first bytes of k_mac
    (
        C::SessionKey::cut_from_digest(&k_enc)
            .expect("digest to be larger than target AES key")
            .to_enum(),
        C::SessionKey::cut_from_digest(&k_mac)
            .expect("digest to be larger than target AES key")
            .to_enum(),
    )
}

#[cfg(test)]
pub mod test {
    use crate::{
        cert::hexslice::HexDisplay, ecdh::shared_secret::TachoSharedSecret,
        session::session_key::TachoSessionKey,
    };
    use elliptic_curve::FieldBytes;
    use hex_literal::hex;
    use p521::NistP521;

    #[test]
    fn test_derive_key_256() {
        use elliptic_curve::FieldBytes;
        let demo_shared_secret: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let demo_shared_secret =
            FieldBytes::<p256::NistP256>::try_from(demo_shared_secret).unwrap();
        let demo_shared_secret = TachoSharedSecret::P256(demo_shared_secret.into());

        let n_picc = [1, 2, 3, 4, 5, 6, 7, 8];
        let (k_enc, k_mac) = demo_shared_secret.derive_key(n_picc);

        println!("k_enc: {}", HexDisplay(k_enc.as_bytes()));
        println!("k_mac: {}", HexDisplay(k_mac.as_bytes()));
        assert_eq!(
            k_enc,
            TachoSessionKey::CS1(hex!("5C 02 EF 74 9F 45 70 CF 6C CA E0 A9 69 58 DD 1E").into())
        );
        assert_eq!(
            k_mac,
            TachoSessionKey::CS1(hex!("A3 98 16 11 A7 92 CC 7B C3 EF B8 CE 05 10 F1 11").into())
        );
    }

    #[test]
    fn test_derive_key_384() {
        use elliptic_curve::FieldBytes;
        let demo_shared_secret: [u8; 48] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, //
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        ];
        let demo_shared_secret =
            FieldBytes::<p384::NistP384>::try_from(demo_shared_secret).unwrap();
        let demo_shared_secret = TachoSharedSecret::P384(demo_shared_secret.into());

        let n_picc = [1, 2, 3, 4, 5, 6, 7, 8];
        let (k_enc, k_mac) = demo_shared_secret.derive_key(n_picc);

        println!("k_enc: {}", HexDisplay(k_enc.as_bytes()));
        println!("k_mac: {}", HexDisplay(k_mac.as_bytes()));
        assert_eq!(
            k_enc,
            TachoSessionKey::CS2(
                hex!("53 C1 9C D5 83 E7 82 EB A7 42 F0 A2 94 10 E9 81 C4 CC 00 95 9F 57 21 08")
                    .into()
            )
        );
        assert_eq!(
            k_mac,
            TachoSessionKey::CS2(
                hex!("1D 9E 1A 39 E7 01 06 21 A4 F1 7F 94 D3 A5 BC 9C 1B 8E 83 D2 D7 15 6A 93")
                    .into()
            )
        );
    }

    #[test]
    fn test_derive_key_512() {
        let demo_shared_secret: [u8; 64] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, //
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, //
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];

        let demo_shared_secret = TachoSharedSecret::BP512(demo_shared_secret);

        let n_picc = [1, 2, 3, 4, 5, 6, 7, 8];
        let (k_enc, k_mac) = demo_shared_secret.derive_key(n_picc);

        println!("k_enc: {}", HexDisplay(k_enc.as_bytes()));
        println!("k_mac: {}", HexDisplay(k_mac.as_bytes()));
        assert_eq!(
            k_enc,
            TachoSessionKey::CS3(hex!(
                "E3 15 BA 35 74 00 F6 AC 21 35 93 F2 C9 13 15 E9 CC F7 41 CA 69 D3 ED F6 3F 9C 6A FB 9A 7E 66 59"
            ).into())
        );
        assert_eq!(
            k_mac,
            TachoSessionKey::CS3(hex!(
                "17 6E 6F 13 0D AE E3 05 52 4B 01 F6 B1 09 DF 91 01 B4 3D 04 70 62 B4 0B BF 61 2B B8 F5 9C DC 8E"
            ).into())
        );
    }

    #[test]
    fn test_derive_key_521() {
        let demo_shared_secret: [u8; 66] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, //
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, //
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, //
            64, 65,
        ];

        let demo_shared_secret = FieldBytes::<NistP521>::try_from(demo_shared_secret).unwrap();
        let demo_shared_secret = TachoSharedSecret::P521(demo_shared_secret.into());

        let n_picc = [1, 2, 3, 4, 5, 6, 7, 8];
        let (k_enc, k_mac) = demo_shared_secret.derive_key(n_picc);

        println!("k_enc: {}", HexDisplay(k_enc.as_bytes()));
        println!("k_mac: {}", HexDisplay(k_mac.as_bytes()));
        assert_eq!(
            k_enc,
            TachoSessionKey::CS3(hex!(
                "E1 0B 54 B7 5A 9C 6D 67 8F E4 1D 0C 5F 41 50 8E 83 3D 72 8A E0 DD 43 8A BA 3C 27 E1 01 C0 FB 77"
            ).into())
        );
        assert_eq!(
            k_mac,
            TachoSessionKey::CS3(hex!(
                "9F DF FC 20 B1 DA 74 4B EC 9E 0F 8C B1 84 68 A3 20 BD 2D 4F C8 84 4E B5 F9 F4 34 17 65 1D 62 A4"
            ).into())
        );
    }
}
