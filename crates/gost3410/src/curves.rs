//! The three curves NCA RK uses, in short Weierstrass form, on RustCrypto's `primeorder`
//! (complete addition formulas, constant-time scalar multiplication) and `primefield`
//! (Montgomery arithmetic on `crypto-bigint`).
//!
//! TC26 256-A has cofactor 4. The complete formulas are exact for points of the order-q subgroup,
//! the only points this crate works with: the generator, and public keys, which
//! [`VerifyingKey`](crate::VerifyingKey) checks to lie in the subgroup.

// primefield 0.14's `monty_field_params!` still calls the deprecated `Uint::bits`.
#![allow(deprecated)]

use elliptic_curve::{
    bigint::{U256, U512},
    consts::{U32, U64},
};

/// Defines a field (base or scalar) as a Montgomery prime field.
macro_rules! field {
    ($params:ident, $name:ident, $uint:ty, $modulus:expr, $nonresidue:expr, $doc:expr) => {
        primefield::monty_field_params! {
            name: $params,
            modulus: $modulus,
            uint: $uint,
            byte_order: primefield::ByteOrder::BigEndian,
            multiplicative_generator: $nonresidue,
            doc: $doc
        }
        primefield::monty_field_element! {
            name: $name,
            params: $params,
            uint: $uint,
            doc: $doc
        }
        primefield::monty_field_arithmetic! {
            name: $name,
            params: $params,
            uint: $uint
        }
    };
}

/// Defines a curve: its type, scalar field, and `elliptic-curve`/`primeorder` traits.
macro_rules! curve {
    (
        $(#[$attr:meta])*
        $curve:ident, $module:ident, $uint:ty, $bytes:ty, $field:ty,
        order: $order:expr, nonresidue: $qnr:expr, cofactor: $h:expr,
        arithmetic: $arith:ty, a: $a:expr, b: $b:expr, gx: $gx:expr, gy: $gy:expr,
        name: $cname:expr, oids: [$($oid:expr),+ $(,)?]
    ) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
        pub struct $curve;

        /// The scalar field of the curve, and its point types.
        pub mod $module {
            #[allow(unused_imports)]
            use super::*;
            #[allow(unused_imports)]
            use elliptic_curve::{
                Curve as _,
                bigint::{Odd, cpubits},
                ff::PrimeField,
                ops::BatchInvert,
                scalar::{FromUintUnchecked, IsHigh},
                subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
            };
            use primeorder::wnaf;

            field!(ScalarParams, Scalar, $uint, $order, $qnr, "An integer modulo the curve's subgroup order q.");
            primefield::monty_field_reduce! {
                name: Scalar,
                params: ScalarParams,
                uint: $uint,
            }
            elliptic_curve::scalar_impls!($curve, Scalar);
            wnaf::impl_wnaf_size_for_scalar!(Scalar);

            impl AsRef<Scalar> for Scalar {
                fn as_ref(&self) -> &Scalar {
                    self
                }
            }

            impl FromUintUnchecked for Scalar {
                type Uint = $uint;

                fn from_uint_unchecked(uint: Self::Uint) -> Self {
                    Self::from_uint_unchecked(uint)
                }
            }

            impl IsHigh for Scalar {
                fn is_high(&self) -> Choice {
                    let half: $uint = $curve::ORDER.as_ref().shr_vartime(1);
                    self.to_canonical().ct_gt(&half)
                }
            }

            /// A point in affine coordinates.
            pub type AffinePoint = primeorder::AffinePoint<$curve>;
            /// A point in projective coordinates.
            pub type ProjectivePoint = primeorder::ProjectivePoint<$curve>;

            impl elliptic_curve::Curve for $curve {
                type FieldBytesSize = $bytes;
                type Uint = $uint;
                const ORDER: Odd<$uint> = Odd::<$uint>::from_be_hex($order);
            }

            impl elliptic_curve::PrimeCurve for $curve {}

            impl elliptic_curve::point::PointCompression for $curve {
                const COMPRESS_POINTS: bool = false;
            }

            impl elliptic_curve::CurveArithmetic for $curve {
                type AffinePoint = AffinePoint;
                type ProjectivePoint = ProjectivePoint;
                type Scalar = Scalar;
            }

            impl elliptic_curve::hazmat::FieldArithmetic for $curve {
                type FieldElement = $field;
            }

            impl elliptic_curve::PrimeCurveArithmetic for $curve {
                type CurveGroup = ProjectivePoint;
            }

            impl primeorder::PrimeCurveParams for $curve {
                type PointArithmetic = $arith;
                type Backend = primeorder::mul_backend::VariableOnly;
                const EQUATION_A: $field = $a;
                const EQUATION_B: $field = <$field>::from_hex_vartime($b);
                const GENERATOR: ($field, $field) = (
                    <$field>::from_hex_vartime($gx),
                    <$field>::from_hex_vartime($gy),
                );
            }

            impl crate::GostCurve for $curve {
                const NAME: &'static str = $cname;
                const COFACTOR: u32 = $h;
                const PARAM_SET_OIDS: &'static [&'static str] = &[$($oid),+];
            }
        }
    };
}

/// The base field of the 256-bit curves: p = 2^256 - 617.
pub mod p256 {
    use super::U256;
    #[allow(unused_imports)]
    use elliptic_curve::{
        ff::PrimeField,
        ops::BatchInvert,
        subtle::{Choice, ConstantTimeEq, CtOption},
    };
    field!(
        FieldParams,
        FieldElement,
        U256,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
        7,
        "An element of the field modulo p = 2^256 - 617."
    );
    impl BatchInvert for FieldElement {}
}

/// The base field of TC26 512-A: p = 2^512 - 569.
pub mod p512 {
    use super::U512;
    #[allow(unused_imports)]
    use elliptic_curve::{
        ff::PrimeField,
        ops::BatchInvert,
        subtle::{Choice, ConstantTimeEq, CtOption},
    };
    field!(
        FieldParams,
        FieldElement,
        U512,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
        5,
        "An element of the field modulo p = 2^512 - 569."
    );
    impl BatchInvert for FieldElement {}
}

curve!(
    /// GOST R 34.10-2001 CryptoPro-A (= TC26 256-B), NCA's GOST 34.310-2004 keys.
    CryptoProA, cryptopro_a, U256, U32, p256::FieldElement,
    order: "ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
    nonresidue: 2, cofactor: 1,
    arithmetic: primeorder::point_arithmetic::EquationAIsMinusThree,
    a: p256::FieldElement::from_u64(3).neg(),
    b: "00000000000000000000000000000000000000000000000000000000000000a6",
    gx: "0000000000000000000000000000000000000000000000000000000000000001",
    gy: "8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14",
    name: "GostR3410-2001-CryptoPro-A",
    oids: ["1.2.398.3.10.1.1.1.1.1", "1.2.643.2.2.35.1", "1.2.643.7.1.2.1.1.2"]
);

curve!(
    /// TC26 GOST R 34.10-2012 256-bit paramSetA (cofactor 4), NCA's GOST 2015 256-bit keys.
    Tc26_256A, tc26_256a, U256, U32, p256::FieldElement,
    order: "400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67",
    nonresidue: 5, cofactor: 4,
    arithmetic: primeorder::point_arithmetic::EquationAIsGeneric,
    a: p256::FieldElement::from_hex_vartime(
        "c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"
    ),
    b: "295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513",
    gx: "91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28",
    gy: "32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c",
    name: "Tc26-Gost-3410-12-256-paramSetA",
    oids: ["1.2.398.3.10.1.1.2.1.1", "1.2.643.7.1.2.1.1.1"]
);

curve!(
    /// TC26 GOST R 34.10-2012 512-bit paramSetA, NCA's GOST 2015 512-bit keys.
    Tc26_512A, tc26_512a, U512, U64, p512::FieldElement,
    order: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
    nonresidue: 2, cofactor: 1,
    arithmetic: primeorder::point_arithmetic::EquationAIsMinusThree,
    a: p512::FieldElement::from_u64(3).neg(),
    b: "e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
    gx: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
    gy: "7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
    name: "Tc26-Gost-3410-12-512-paramSetA",
    oids: ["1.2.398.3.10.1.1.2.2.1", "1.2.643.7.1.2.1.2.1"]
);
