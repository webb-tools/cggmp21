//! # Threshold ECDSA based on [CGGMP21]
//!
//! [CGGMP21] is a state-of-art ECDSA TSS protocol that supports 1-round signing (given preprocessing).
//!
//! This crate implements:
//! * General threshold (i.e., t-out-of-n) and full threshold (i.e., n-out-of-n) key generation
//! * (3+1)-round general threshold and full threshold signing
//! * Auxiliary info generation protocol
//! * Key refresh for full-threshold keys
//!
//! We also provide auxiliary tools like:
//! * [Secret key reconstruction](crate::key_share::reconstruct_secret_key) (exporting a key)
//! * [Trusted dealer](crate::trusted_dealer) (importing a key)
//!
//! This crate **does not** (currently) support:
//! * Key refresh for general thresholds
//! * Identifiable abort
//! * The (5+1)-round signing protocol
//!
//! ## Running the protocol
//!
//! ### Networking
//! In order to run the protocol, you need to define how each signer can communicate with other signers. We
//! use a [`round_based`] framework that handles networking. Basically, you need to define a stream
//! of `incoming` messages and sink of `outgoing` messages:
//!
//! ```rust,ignore
//! let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
//! let outgoing: impl Sink<Outgoing<Msg>>;
//! ```
//!
//! where:
//! * `Msg` is a protocol message (e.g., [`signing::msg::Msg`])
//! * [`round_based::Incoming`] and [`round_based::Outgoing`] wrap `Msg` and provide additional data (e.g., sender/recepient)
//! * [`futures::Stream`] and [`futures::Sink`] are well-known async primitives.
//!
//! Then, construct a [`round_based::MpcParty`]:
//! ```rust
//! # type Msg = cggmp21::signing::msg::Msg<cggmp21::supported_curves::Secp256k1, sha2::Sha256>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! let delivery = (incoming, outgoing);
//! let party = round_based::MpcParty::connected(delivery);
//! ```
//!
//! #### Signer indices
//! Each signer in a protocol execution (keygen/signing/etc.) occupies a unique index $i$ ($0 \le i < n$,
//! where $n$ is number of parties overall). For instance, if Signer A occupies index `2`, then all
//! other signers must agree that `i=2` corresponds to Signer A.
//!
//! Assuming you have a PKI (which is anyway needed to comply with [security requirements]) and each signer
//! has a public key uniqely idenitifying that signer, you can assign unique indexes to the signers as follows:
//! 1. Make a list of signers' public keys
//! 2. Sort the list of public keys
//! 3. Assign each signer an index `i` such that `i` corresponds to the position of the signer's public key in the 
//!    sorted list of public keys
//!
//! [security requirements]: #security
//!
//! #### Security
//! Make sure that the communication layer complies with security requirements:
//! * All messages sent must be authenticated
//! * All p2p messages must be encrypted
//!
//! ### Execution ID
//! When executing a protocol, signers need to agree on a unique identifier of the protocol execution [`ExecutionId`].
//! The Execution ID needs to be unique per protocol execution (keygen/signing/etc.), otherwise it may compromise security.
//! The Execution ID needs to be the same for all signers taking part in the protocol, otherwise protocol will abort.
//! Execution ID **does not** need to be secret.
//!
//! Once signers can talk to each other and share an execution ID, they're ready to generate a key!
//!
//! ### Distributed Key Generation
//! ```rust,no_run
//! # async fn doc() -> Result<(), cggmp21::KeygenError> {
//! # type Msg = cggmp21::keygen::msg::threshold::Msg<cggmp21::supported_curves::Secp256k1, cggmp21::security_level::ReasonablySecure, sha2::Sha256>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! # let delivery = (incoming, outgoing);
//! # let party = round_based::MpcParty::connected(delivery);
//! #
//! use cggmp21::supported_curves::Secp256k1;
//! # use rand_core::OsRng;
//!
//! let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
//! let i = /* signer index (0 <= i < n) */
//! # 0;
//! let n = /* number of signers taking part in key generation */
//! # 3;
//! let t = /* threshold */
//! # 2;
//!
//! let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, i, n)
//!     .set_threshold(t)
//!     .start(&mut OsRng, party)
//!     .await?;
//! # Ok(()) }
//! ```
//! This code outputs [`IncompleteKeyShare`]. Note that this key share is not yet ready to do signing. You need to “complete” it
//! by generating auxiliary info (see below).
//!
//! ### Auxiliary info generation
//! After key generation, all signers need to take part in generation of auxiliary information. Make sure all signers occupy exactly
//! the same indices as at keygen.
//! ```rust,no_run
//! # async fn doc() -> Result<(), cggmp21::KeyRefreshError> {
//! # type Msg = cggmp21::key_refresh::msg::aux_only::Msg<sha2::Sha256, cggmp21::security_level::ReasonablySecure>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! # let delivery = (incoming, outgoing);
//! # let party = round_based::MpcParty::connected(delivery);
//! #
//! # use rand_core::OsRng;
//! // Prime generation can take a while
//! let pregenerated_primes = cggmp21::PregeneratedPrimes::generate(&mut OsRng);
//!
//! let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
//! let i = /* signer index, same as at keygen */
//! # 0;
//! let n = /* number of signers */
//! # 3;
//!
//! let aux_info = cggmp21::aux_info_gen(eid, i, n, pregenerated_primes)
//!     .start(&mut OsRng, party)
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! After keygen and aux info gen are done, you can make a “complete” key share that can be used for signing:
//! ```rust,no_run
//! # fn main() -> Result<(), cggmp21::key_share::InvalidKeyShare> {
//! # let (incomplete_key_share, aux_info): (cggmp21::IncompleteKeyShare<cggmp21::supported_curves::Secp256k1>, cggmp21::key_share::AuxInfo) = unimplemented!();
//! let key_share = cggmp21::KeyShare::make(incomplete_key_share, aux_info)?;
//! # Ok(()) }
//! ```
//!
//! ### Signing
//! Once a complete key share is obtained, signers can sign or generate presignatures. In either case, the required threshold t of
//! signers must take part in the protocol. Each signer needs to be assigned a unique index
//! `0 <= i < t`, but we also need to know which index each signer had at keygen.
//!
//! In the example below, we do a full signing:
//! ```rust,no_run
//! # async fn doc() -> Result<(), cggmp21::SigningError> {
//! # type Msg = cggmp21::signing::msg::Msg<cggmp21::supported_curves::Secp256k1, sha2::Sha256>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! # let delivery = (incoming, outgoing);
//! # let party = round_based::MpcParty::connected(delivery);
//! #
//! # use rand_core::OsRng; use sha2::Sha256;
//! # const MIN_SIGNERS: usize = 3;
//! #
//! let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
//!
//! let i = /* signer index (0 <= i < min_signers) */
//! # 0;
//! let parties_indexes_at_keygen: [u16; MIN_SIGNERS] =
//!     /* parties_indexes_at_keygen[i] is the index the i-th party had at keygen */
//! # [0, 1, 2];
//! let key_share = /* completed key share */
//! # {let s: cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1> = unimplemented!(); s};
//!
//! let data_to_sign = cggmp21::DataToSign::digest::<Sha256>(b"data to be signed");
//!
//! let signature = cggmp21::signing(eid, i, &parties_indexes_at_keygen, &key_share)
//!     .sign(&mut OsRng, party, data_to_sign)
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! Alternatively, you can generate a presignature and later use it to sign:
//! 1. Use [`SigningBuilder::generate_presignature`] to run the presignature generation protocol
//! 2. Later, when a signing request is received, each signer issues a partial signature using
//!    [`Presignature::issue_partial_signature`]
//! 3. The requisite number of partial signatures can be combined using [`PartialSignature::combine`] to
//!    obtain a full signature
//!
//! **Never reuse presignatures!** If you use the same presignature to sign two different messages,
//! it leaks information about key shares to anyone who can observe the signatures.
//!
//! ## Differences between the implementation and [CGGMP21]
//! [CGGMP21] only defines a full threshold protocol. To support general thresholds,
//! we defined our own CGGMP21-like key generation and threshold signing
//! protocols. However, we keep both
//! general threshold and full threshold versions of the protocols in the crate, so if you opt for the full threshold
//! protocol, you will be running the original protocol defined in the paper.
//!
//! There are other (small) differences in the implementation compared to the original paper (mostly typo fixes);
//! they are all documented in [the spec].
//!
//! [CGGMP21]: https://ia.cr/2021/060
//! [the spec]: https://github.com/dfns-labs/cggmp21/tree/m/docs/spec.pdf
//! [security guidelines]: #security-guidelines

#![allow(
    non_snake_case,
    mixed_script_confusables,
    uncommon_codepoints,
    clippy::too_many_arguments,
    clippy::nonminimal_bool
)]
#![forbid(clippy::disallowed_methods, missing_docs, unsafe_code)]
#![cfg_attr(not(test), forbid(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub use {
    generic_ec, paillier_zk, paillier_zk::libpaillier, paillier_zk::libpaillier::unknown_order,
    round_based,
};

use generic_ec::{coords::HasAffineX, hash_to_curve::FromHash, Curve, Point, Scalar};
use key_share::AnyKeyShare;
use round_based::PartyIndex;
use security_level::SecurityLevel;
use signing::SigningBuilder;

mod errors;
mod execution_id;
pub mod key_refresh;
pub mod key_share;
pub mod keygen;
pub mod progress;
pub mod security_level;
pub mod signing;
pub mod supported_curves;
mod utils;
mod zk;

#[cfg(feature = "spof")]
pub mod trusted_dealer;

/// Defines default choice for digest and security level used across the crate
mod default_choice {
    pub type Digest = sha2::Sha256;
    pub type SecurityLevel = crate::security_level::ReasonablySecure;
}

pub use self::execution_id::ExecutionId;
pub use self::{
    key_refresh::{KeyRefreshError, PregeneratedPrimes},
    key_share::{IncompleteKeyShare, KeyShare},
    keygen::KeygenError,
    signing::{DataToSign, PartialSignature, Presignature, Signature, SigningError},
};

/// Distributed key generation protocol
///
/// Each party of the protocol should have uniquely assigned index $i$ such that $0 \le i < n$
/// (where $n$ is amount of parties in the protocol).
///
/// [KeygenBuilder]: keygen::KeygenBuilder
/// [ReasonablySecure]: security_level::ReasonablySecure
/// [`set_threshold`]: keygen::GenericKeygenBuilder::set_threshold
pub fn keygen<E>(eid: ExecutionId, i: u16, n: u16) -> keygen::KeygenBuilder<E>
where
    E: Curve,
    Scalar<E>: FromHash,
{
    keygen::KeygenBuilder::new(eid, i, n)
}

/// Protocol for finalizing the keygen by generating aux info.
///
/// PregeneratedPrimes can be obtained with [`key_refresh::PregeneratedPrimes::generate`]
///
/// Index `i` of party should be the same as index [inside the key share] you are
/// going to use this aux info with. Number of parties `n` should be the same [as number
/// of signers] sharing the key.
///
/// Outputs [`AuxInfo`](key_share::AuxInfo) that can be used to "complete" [`IncompleteKeyShare`]
/// using [`KeyShare::make`].
///
/// [inside the key share]: key_share::DirtyIncompleteKeyShare::i
/// [as number of signers]: IncompleteKeyShare::n
pub fn aux_info_gen<L>(
    eid: ExecutionId,
    i: u16,
    n: u16,
    pregenerated: key_refresh::PregeneratedPrimes<L>,
) -> key_refresh::AuxInfoGenerationBuilder<L>
where
    L: SecurityLevel,
{
    key_refresh::GenericKeyRefreshBuilder::new_aux_gen(eid, i, n, pregenerated)
}

/// Protocol for performing key refresh. Can be used to perform initial refresh
/// with aux info generation, or for a refresh of a complete key share.
///
/// Doesn't work with general-threshold key shares at this point.
///
/// PregeneratedPrimes can be obtained with [`key_refresh::PregeneratedPrimes::generate`]
pub fn key_refresh<'a, E, L>(
    eid: ExecutionId<'a>,
    key_share: &'a impl AnyKeyShare<E>,
    pregenerated: key_refresh::PregeneratedPrimes<L>,
) -> key_refresh::KeyRefreshBuilder<'a, E, L>
where
    E: Curve,
    L: SecurityLevel,
{
    key_refresh::KeyRefreshBuilder::new(eid, key_share, pregenerated)
}

/// Protocol for generating a signature or presignature
pub fn signing<'r, E, L>(
    eid: ExecutionId<'r>,
    i: PartyIndex,
    parties_indexes_at_keygen: &'r [PartyIndex],
    key_share: &'r KeyShare<E, L>,
) -> SigningBuilder<'r, E, L>
where
    E: Curve,
    Point<E>: HasAffineX<E>,
    Scalar<E>: FromHash,
    L: SecurityLevel,
{
    SigningBuilder::new(eid, i, parties_indexes_at_keygen, key_share)
}

#[cfg(test)]
mod tests {
    use digest::Digest;
    use generic_ec::Curve;
    use serde::{de::DeserializeOwned, Serialize};

    use crate::security_level::SecurityLevel;

    macro_rules! ensure_certain_types_impl_serde {
        ($($type:ty),+,) => {
            fn impls_serde<T: Serialize + DeserializeOwned>() {}

            #[allow(dead_code)]
            fn ensure_types_impl_serde<E: Curve, L: SecurityLevel, D: Digest>() {$(
                impls_serde::<$type>();
            )+}
        }
    }

    ensure_certain_types_impl_serde! {
        crate::key_share::KeyShare<E, L>,
        crate::key_share::IncompleteKeyShare<E>,
        crate::key_share::AuxInfo<L>,

        crate::key_share::DirtyKeyShare<E, L>,
        crate::key_share::DirtyIncompleteKeyShare<E>,
        crate::key_share::DirtyAuxInfo<L>,

        crate::keygen::msg::non_threshold::Msg<E, L, D>,
        crate::keygen::msg::threshold::Msg<E, L, D>,

        crate::key_refresh::msg::aux_only::Msg<D, L>,
        crate::key_refresh::msg::non_threshold::Msg<E, D, L>,

        crate::signing::msg::Msg<E, D>,
        crate::signing::Presignature<E>,
        crate::signing::PartialSignature<E>,
        crate::signing::Signature<E>,
    }
}
