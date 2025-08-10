use eyre::bail;

use crate::ec::{affine_point::TachoAffinePoint, non_zero_scalar::TachoNonZeroScalar};

use super::shared_secret::TachoSharedSecret;

/// Low-level Elliptic Curve Diffie-Hellman (ECDH) function.
///
///
pub fn tacho_diffie_hellman(
    secret_key: &TachoNonZeroScalar,
    public_key: &TachoAffinePoint<'_>,
) -> eyre::Result<TachoSharedSecret> {
    Ok(match (secret_key, public_key) {
        (TachoNonZeroScalar::P256(sk_non_zero_scalar), TachoAffinePoint::P256(pk_affine)) => {
            let shared_secret =
                elliptic_curve::ecdh::diffie_hellman(sk_non_zero_scalar, *pk_affine);
            TachoSharedSecret::P256(shared_secret)
        }

        (TachoNonZeroScalar::P384(sk_non_zero_scalar), TachoAffinePoint::P384(pk_affine)) => {
            let shared_secret =
                elliptic_curve::ecdh::diffie_hellman(sk_non_zero_scalar, *pk_affine);
            TachoSharedSecret::P384(shared_secret)
        }

        (TachoNonZeroScalar::P521(sk_non_zero_scalar), TachoAffinePoint::P521(pk_affine)) => {
            let shared_secret =
                elliptic_curve::ecdh::diffie_hellman(sk_non_zero_scalar, *pk_affine);
            TachoSharedSecret::P521(shared_secret)
        }
        (TachoNonZeroScalar::BP256(sk_non_zero_scalar), TachoAffinePoint::BP256(pk_affine)) => {
            let shared_secret =
                elliptic_curve::ecdh::diffie_hellman(sk_non_zero_scalar, *pk_affine);
            TachoSharedSecret::BP256(shared_secret)
        }
        (TachoNonZeroScalar::BP384(sk_non_zero_scalar), TachoAffinePoint::BP384(pk_affine)) => {
            let shared_secret =
                elliptic_curve::ecdh::diffie_hellman(sk_non_zero_scalar, *pk_affine);
            TachoSharedSecret::BP384(shared_secret)
        }

        (TachoNonZeroScalar::BP512(_), TachoAffinePoint::BP512(_)) => {
            todo!("BP512 ecdh diffie_hellman")
        }

        _ => bail!("ecdh: invalid combination of secret key and public key domain"),
    })
}
