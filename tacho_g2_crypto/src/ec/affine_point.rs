/// Raw Public key, used mainly for ECDH
///
/// Affine point type for a given curve.
pub enum TachoAffinePoint<'a> {
    /// Nist
    P256(&'a p256::AffinePoint),

    /// Nist
    P384(&'a p384::AffinePoint),

    /// Nist
    P521(&'a p521::AffinePoint),

    /// Brainpool
    BP256(&'a bp256::r1::AffinePoint),

    /// Brainpool
    BP384(&'a bp384::r1::AffinePoint),

    /// Brainpool
    BP512(()),
}
