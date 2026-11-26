//! Signing and checking.

use core::fmt;

use elliptic_curve::{
    AffinePoint, FieldBytes, FieldBytesSize, NonZeroScalar, ProjectivePoint, PublicKey, Scalar,
    SecretKey,
    array::typenum::Unsigned,
    ff::{Field, PrimeField},
    group::Group,
    ops::{MulByGeneratorVartime, Reduce},
    point::AffineCoordinates,
    sec1::ToSec1Point,
    subtle::{Choice, ConstantTimeEq},
};
use hmac::{KeyInit, Mac};
use signature::{
    Error, Keypair, Result, Verifier,
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    rand_core::TryCryptoRng,
};
use zeroize::{Zeroize, Zeroizing};

use crate::GostCurve;

/// The largest field size in bytes (TC26 512-A).
const MAX: usize = 64;

/// Field-size bytes, big-endian, from `le` (little-endian, at most the field size).
fn be_from_le<C: GostCurve>(le: &[u8]) -> Result<FieldBytes<C>> {
    let n = FieldBytesSize::<C>::USIZE;
    if le.len() > n {
        return Err(Error::new());
    }
    let mut out = FieldBytes::<C>::default();
    for (o, b) in out.iter_mut().rev().zip(le) {
        *o = *b;
    }
    Ok(out)
}

/// e = hash (read little-endian) mod q, or 1 when that is 0.
fn hash_to_e<C: GostCurve>(hash: &[u8]) -> Result<Scalar<C>> {
    let e = <Scalar<C> as Reduce<FieldBytes<C>>>::reduce(&be_from_le::<C>(hash)?);
    Ok(Scalar::<C>::conditional_select_ct(
        &e,
        &Scalar::<C>::ONE,
        e.is_zero(),
    ))
}

/// The x coordinate of `p` reduced mod q.
fn x_mod_q<C: GostCurve>(p: &AffinePoint<C>) -> Scalar<C> {
    <Scalar<C> as Reduce<FieldBytes<C>>>::reduce(&p.x())
}

trait SelectCt: Sized {
    fn conditional_select_ct(a: &Self, b: &Self, choice: Choice) -> Self;
}

impl<F: elliptic_curve::subtle::ConditionallySelectable> SelectCt for F {
    fn conditional_select_ct(a: &Self, b: &Self, choice: Choice) -> Self {
        F::conditional_select(a, b, choice)
    }
}

// ------------------------------------------------------------------ signatures

/// A GOST R 34.10 signature: (r, s), both in [1, q-1].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature<C: GostCurve> {
    r: Scalar<C>,
    s: Scalar<C>,
}

impl<C: GostCurve> Signature<C> {
    /// From r and s; fails when either is 0.
    pub fn from_scalars(r: Scalar<C>, s: Scalar<C>) -> Result<Self> {
        if bool::from(r.is_zero() | s.is_zero()) {
            return Err(Error::new());
        }
        Ok(Signature { r, s })
    }

    /// r
    pub fn r(&self) -> &Scalar<C> {
        &self.r
    }

    /// s
    pub fn s(&self) -> &Scalar<C> {
        &self.s
    }

    /// NCA RK's form: r || s, each little-endian and field-size long.
    pub fn from_nca_bytes(b: &[u8]) -> Result<Self> {
        let n = FieldBytesSize::<C>::USIZE;
        if b.len() != 2 * n {
            return Err(Error::new());
        }
        let (r, s) = b.split_at(n);
        Self::from_scalars(scalar_le::<C>(r)?, scalar_le::<C>(s)?)
    }

    /// NCA RK's form: r || s, each little-endian and field-size long. Writes 2 × the field
    /// size bytes into `out` and returns them.
    pub fn to_nca_bytes<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        let n = FieldBytesSize::<C>::USIZE;
        let out = out.get_mut(..2 * n).ok_or_else(Error::new)?;
        let (r, s) = out.split_at_mut(n);
        for (dst, v) in [(r, self.r), (s, self.s)] {
            for (o, b) in dst.iter_mut().zip(v.to_repr().iter().rev()) {
                *o = *b;
            }
        }
        Ok(out)
    }

    /// The standard GOST R 34.10 form: s || r, each big-endian and field-size long.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let n = FieldBytesSize::<C>::USIZE;
        if b.len() != 2 * n {
            return Err(Error::new());
        }
        let (s, r) = b.split_at(n);
        Self::from_scalars(scalar_be::<C>(r)?, scalar_be::<C>(s)?)
    }

    /// The standard GOST R 34.10 form: s || r, each big-endian. Writes 2 × the field size
    /// bytes into `out` and returns them.
    pub fn to_bytes<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        let n = FieldBytesSize::<C>::USIZE;
        let out = out.get_mut(..2 * n).ok_or_else(Error::new)?;
        let (s, r) = out.split_at_mut(n);
        s.copy_from_slice(&self.s.to_repr());
        r.copy_from_slice(&self.r.to_repr());
        Ok(out)
    }
}

impl<C: GostCurve> fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &self.r)
            .field("s", &self.s)
            .finish()
    }
}

/// A scalar in [0, q-1] from big-endian bytes; fails at q and above.
fn scalar_be<C: GostCurve>(b: &[u8]) -> Result<Scalar<C>> {
    let mut fb = FieldBytes::<C>::default();
    if b.len() != fb.len() {
        return Err(Error::new());
    }
    fb.copy_from_slice(b);
    Option::from(Scalar::<C>::from_repr(fb)).ok_or_else(Error::new)
}

/// A scalar in [0, q-1] from little-endian bytes; fails at q and above.
fn scalar_le<C: GostCurve>(b: &[u8]) -> Result<Scalar<C>> {
    if b.len() != FieldBytesSize::<C>::USIZE {
        return Err(Error::new());
    }
    Option::from(Scalar::<C>::from_repr(be_from_le::<C>(b)?)).ok_or_else(Error::new)
}

// ------------------------------------------------------------------ keys

/// A public key: a point of the order-q subgroup, not the identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey<C: GostCurve> {
    point: AffinePoint<C>,
}

impl<C: GostCurve> VerifyingKey<C> {
    /// From an affine point; fails for the identity or (TC26 256-A) a point outside the
    /// order-q subgroup.
    pub fn from_affine(point: AffinePoint<C>) -> Result<Self> {
        let p = ProjectivePoint::<C>::from(point);
        if bool::from(p.is_identity()) {
            return Err(Error::new());
        }
        if C::COFACTOR != 1 {
            // q·P = O  <=>  (q-1)·P + P = O
            let q_minus_1 = -Scalar::<C>::ONE;
            if !bool::from((p * q_minus_1 + p).is_identity()) {
                return Err(Error::new());
            }
        }
        Ok(VerifyingKey { point })
    }

    /// NCA RK's form: x || y, each little-endian and field-size long (the content of the
    /// certificate's public-key OCTET STRING).
    pub fn from_nca_bytes(b: &[u8]) -> Result<Self> {
        let n = FieldBytesSize::<C>::USIZE;
        if b.len() != 2 * n {
            return Err(Error::new());
        }
        let mut sec1 = [0u8; 1 + 2 * MAX];
        let sec1 = sec1.get_mut(..1 + 2 * n).ok_or_else(Error::new)?;
        let (tag, xy) = sec1.split_at_mut(1);
        tag.copy_from_slice(&[4]);
        let (x, y) = xy.split_at_mut(n);
        let (bx, by) = b.split_at(n);
        for (dst, src) in [(x, bx), (y, by)] {
            for (o, v) in dst.iter_mut().zip(src.iter().rev()) {
                *o = *v;
            }
        }
        let pk = PublicKey::<C>::from_sec1_bytes(sec1).map_err(|_| Error::new())?;
        Self::from_affine(*pk.as_affine())
    }

    /// NCA RK's form: x || y, each little-endian. Writes 2 × the field size bytes.
    pub fn to_nca_bytes<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        let n = FieldBytesSize::<C>::USIZE;
        let out = out.get_mut(..2 * n).ok_or_else(Error::new)?;
        let enc = self.point.to_sec1_point(false);
        let xy = enc.as_bytes().get(1..).ok_or_else(Error::new)?;
        let (x, y) = xy.split_at(n);
        let (ox, oy) = out.split_at_mut(n);
        for (dst, src) in [(ox, x), (oy, y)] {
            for (o, v) in dst.iter_mut().zip(src.iter().rev()) {
                *o = *v;
            }
        }
        Ok(out)
    }

    /// The point.
    pub fn as_affine(&self) -> &AffinePoint<C> {
        &self.point
    }
}

impl<C: GostCurve> fmt::Debug for VerifyingKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("curve", &C::NAME)
            .finish_non_exhaustive()
    }
}

impl<C: GostCurve> PrehashVerifier<Signature<C>> for VerifyingKey<C> {
    /// Checks `sig` over `prehash`, the hash as NCA gives it (little-endian integer, at most
    /// the field size).
    fn verify_prehash(&self, prehash: &[u8], sig: &Signature<C>) -> Result<()> {
        let e = hash_to_e::<C>(prehash)?;
        let v = Option::<Scalar<C>>::from(e.invert()).ok_or_else(Error::new)?;
        let z1 = sig.s * v;
        let z2 = -(sig.r * v);
        let c = ProjectivePoint::<C>::mul_by_generator_vartime(&z1)
            + ProjectivePoint::<C>::from(self.point) * z2;
        if bool::from(c.is_identity()) {
            return Err(Error::new());
        }
        if x_mod_q::<C>(&c.to_affine()) == sig.r {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl<C: GostCurve> Verifier<Signature<C>> for VerifyingKey<C> {
    /// `msg` is the hash (GOST R 34.10 signs a hash; the caller hashes with GOST 34.311 or
    /// Streebog). The same as [`PrehashVerifier::verify_prehash`].
    fn verify(&self, msg: &[u8], sig: &Signature<C>) -> Result<()> {
        self.verify_prehash(msg, sig)
    }
}

/// A private key d in [1, q-1]; wiped when dropped.
#[derive(Clone)]
pub struct SigningKey<C: GostCurve> {
    secret: SecretKey<C>,
    verifying_key: VerifyingKey<C>,
}

impl<C: GostCurve> SigningKey<C> {
    /// From the secret scalar.
    pub fn from_nonzero_scalar(d: NonZeroScalar<C>) -> Result<Self> {
        let secret = SecretKey::<C>::from(d);
        let point = secret.public_key().to_projective().to_affine();
        Ok(SigningKey {
            secret,
            verifying_key: VerifyingKey::from_affine(point)?,
        })
    }

    /// NCA RK's form: d little-endian, at most the field size long (as it is inside a .p12's
    /// PKCS#8 key). Fails for 0 and for q and above.
    pub fn from_nca_bytes(b: &[u8]) -> Result<Self> {
        let be = Zeroizing::new(be_from_le::<C>(b)?);
        let d = Option::<NonZeroScalar<C>>::from(NonZeroScalar::<C>::from_repr(*be))
            .ok_or_else(Error::new)?;
        Self::from_nonzero_scalar(d)
    }

    /// The public key.
    pub fn verifying_key(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }

    /// Signs `prehash` (the hash as NCA gives it: a little-endian integer, at most the field
    /// size) with the hedged nonce, taking 32 fresh bytes from `rng`.
    pub fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> Result<Signature<C>> {
        let mut fresh = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut *fresh).map_err(|_| Error::new())?;
        self.sign_prehash_with_fresh(prehash, &*fresh)
    }

    /// [`SigningKey::sign_prehash_with_rng`] with the fresh bytes given. With the same
    /// `fresh`, the same message gives the same signature (known-answer tests).
    pub fn sign_prehash_with_fresh(&self, prehash: &[u8], fresh: &[u8]) -> Result<Signature<C>> {
        let e = hash_to_e::<C>(prehash)?;
        let d: Scalar<C> = *self.secret.to_nonzero_scalar();
        let key = Zeroizing::new(d.to_repr());
        // a failure needs a 1 in 2^250 event; give up rather than loop forever
        for attempt in 0..8u32 {
            let k = Zeroizing::new(hedged_nonce::<C>(&key, prehash, attempt, fresh));
            if bool::from(k.is_zero()) {
                continue;
            }
            let point = (ProjectivePoint::<C>::generator() * *k).to_affine();
            let r = x_mod_q::<C>(&point);
            if bool::from(r.is_zero()) {
                continue;
            }
            let s = r * d + *k * e;
            if bool::from(s.is_zero()) {
                continue;
            }
            return Ok(Signature { r, s });
        }
        Err(Error::new())
    }
}

impl<C: GostCurve> fmt::Debug for SigningKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("curve", &C::NAME)
            .finish_non_exhaustive()
    }
}

impl<C: GostCurve> ConstantTimeEq for SigningKey<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret
            .to_nonzero_scalar()
            .ct_eq(&other.secret.to_nonzero_scalar())
    }
}

impl<C: GostCurve> Keypair for SigningKey<C> {
    type VerifyingKey = VerifyingKey<C>;

    fn verifying_key(&self) -> VerifyingKey<C> {
        self.verifying_key
    }
}

impl<C: GostCurve> RandomizedPrehashSigner<Signature<C>> for SigningKey<C> {
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> Result<Signature<C>> {
        SigningKey::sign_prehash_with_rng(self, rng, prehash)
    }
}

/// The hedged nonce: 2 × field-size bytes of HMAC-SHA-512(key = d, "GOST R 34.10 nonce" ||
/// fresh || len(hash) || hash || attempt || block), reduced mod q.
fn hedged_nonce<C: GostCurve>(
    key: &FieldBytes<C>,
    hash: &[u8],
    attempt: u32,
    fresh: &[u8],
) -> Scalar<C> {
    let n = FieldBytesSize::<C>::USIZE;
    let mut buf = Zeroizing::new([0u8; 2 * MAX]);
    for (block, chunk) in buf.chunks_mut(64).take((2 * n).div_ceil(64)).enumerate() {
        let Ok(mut m) = <hmac::Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key) else {
            // HMAC takes a key of any length
            continue;
        };
        m.update(b"GOST R 34.10 hedged nonce");
        m.update(&(fresh.len() as u32).to_be_bytes());
        m.update(fresh);
        m.update(&(hash.len() as u32).to_be_bytes());
        m.update(hash);
        m.update(&attempt.to_be_bytes());
        m.update(&(block as u32).to_be_bytes());
        let mut out = m.finalize().into_bytes();
        chunk.copy_from_slice(&out);
        out.zeroize();
    }
    let mut hi = Zeroizing::new(FieldBytes::<C>::default());
    let mut lo = Zeroizing::new(FieldBytes::<C>::default());
    let (h, l) = buf.split_at(n);
    hi.copy_from_slice(h);
    if let Some(l) = l.get(..n) {
        lo.copy_from_slice(l);
    }
    // hi·2^(8n) + lo mod q, with 2^(8n) mod q = (2^(8n) - 1 mod q) + 1
    let mut all_ones = FieldBytes::<C>::default();
    all_ones.iter_mut().for_each(|b| *b = 0xff);
    let shift = <Scalar<C> as Reduce<FieldBytes<C>>>::reduce(&all_ones) + Scalar::<C>::ONE;
    <Scalar<C> as Reduce<FieldBytes<C>>>::reduce(&hi) * shift
        + <Scalar<C> as Reduce<FieldBytes<C>>>::reduce(&lo)
}

#[cfg(test)]
mod tests;
