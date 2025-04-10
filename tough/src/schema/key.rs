#![allow(clippy::use_self)]

//! Handles cryptographic keys and their serialization in TUF metadata files.

use crate::schema::decoded::{Decoded, EcdsaFlex, Hex, RsaPem, Encode};
use crate::schema::error::Result;
use ring::digest::{digest, SHA256};
use ring::signature::{VerificationAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use snafu::OptionExt;
use super::error;


/// Serializes signing keys as defined by the TUF specification. All keys have the format
/// ```json
///  { "keytype" : "KEYTYPE",
///     "scheme" : "SCHEME",
///     "keyval" : "KEYVAL"
///  }
/// ```
/// where:
/// KEYTYPE is a string denoting a public key signature system, such as RSA or ECDSA.
///
/// SCHEME is a string denoting a corresponding signature scheme.  For example: "rsassa-pss-sha256"
/// and "ecdsa-sha2-nistp256".
///
/// KEYVAL is a dictionary containing the public portion of the key:
/// `"keyval" : {"public" : PUBLIC}`
/// where:
///  * `Rsa`: PUBLIC is in PEM format and a string. All RSA keys must be at least 2048 bits.
///  * `Ed25519`: PUBLIC is a 64-byte hex encoded string.
///  * `Ecdsa`: PUBLIC is in PEM format and a string.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
// TRX We use SCREAMING-KEBAB-CASE
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
#[serde(tag = "keytype")]
pub enum Key {
    /// An RSA key.
    Rsa {
        /// The RSA key.
        keyval: RsaKey,
        /// Denotes the key's signature scheme.
        // TRX: We don't use this field, need to skip serializing when generating canonical jon
        #[serde(skip)]
        scheme: RsaScheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
    /// An Ed25519 key.
    Ed25519 {
        /// The Ed25519 key.
        keyval: Ed25519Key,
        /// Denotes the key's signature scheme.
        // TRX: We don't use this field, need to skip serializing when generating canonical jon
        #[serde(skip)]
        scheme: Ed25519Scheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
    /// An EcdsaKey
    #[serde(rename = "ecdsa-sha2-nistp256")]
    Ecdsa {
        /// The Ecdsa key.
        keyval: EcdsaKey,
        /// Denotes the key's signature scheme.
        scheme: EcdsaScheme,
        /// Any additional fields read during deserialization; will not be used.
        #[serde(flatten)]
        _extra: HashMap<String, Value>,
    },
}

/// Used to identify the RSA signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RsaScheme {
    /// `rsassa-pss-sha256`: RSA Probabilistic signature scheme with appendix.
    RsassaPssSha256,
}

// TRX: Required to skip (de)serializing
impl Default for RsaScheme {
    fn default() -> Self {
        RsaScheme::RsassaPssSha256
    }
}

/// Represents a deserialized (decoded) RSA public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct RsaKey {
    /// The public key.
    pub public: Decoded<RsaPem>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

/// Used to identify the `EdDSA` signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Ed25519Scheme {
    /// 'ed25519': Elliptic curve digital signature algorithm based on Twisted Edwards curves.
    Ed25519,
}

// TRX: Required to skip (de)serializing
impl Default for Ed25519Scheme {
    fn default() -> Self {
        Ed25519Scheme::Ed25519
    }
}

/// Represents a deserialized (decoded) Ed25519 public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct Ed25519Key {
    /// The public key.
    pub public: Decoded<Hex>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

/// Used to identify the ECDSA signature scheme in use.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EcdsaScheme {
    /// `ecdsa-sha2-nistp256`: Elliptic Curve Digital Signature Algorithm with NIST P-256 curve
    /// signing and SHA-256 hashing.
    EcdsaSha2Nistp256,
}

/// Represents a deserialized (decoded)  Ecdsa public key.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct EcdsaKey {
    /// The public key.
    pub public: Decoded<EcdsaFlex>,

    /// Any additional fields read during deserialization; will not be used.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Key {
    /// Calculate the key ID for this key.
    // TRX For legacy reasons, we calculate key ids based on the getEncoded/getAByte 
    // methods in sun.security.rsa.RSAPublicKeyImpl and net.i2p.crypto.eddsa.EdDSAPublicKey respectively,
    // so we need to do the same here, instead of using the cjson representation
    pub fn key_id(&self) -> Result<Decoded<Hex>> {

        let keyval: Vec<u8> = match self {
            Key::Ecdsa {
                keyval,
                ..
            } =>
                keyval.public.to_vec(),
            Key::Ed25519 {
                keyval,
                ..
            } =>{
                let mut der_encoded = Vec::with_capacity(44);

                der_encoded.push(0x30);
                der_encoded.push((10 + keyval.public.len()) as u8);
                der_encoded.extend(&[0x30, 5, 0x06, 3, 43, 101, 112, 0x03, 1 + keyval.public.len() as u8, 0]);
                der_encoded.extend(keyval.public.iter());

                der_encoded
            },
            Key::Rsa {
                keyval,
                ..
            } => {
                let as_pem = RsaPem::encode(&keyval.public);
                let (_, as_der) = spki::Document::from_pem(&as_pem).ok().context(error::SpkiDecodeSnafu)?;
                as_der.to_vec()
            },
        };

        // TRX: See comment on key_id, we dont use cjson to calculate key_id
        // let mut buf = Vec::new();
        // let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        // self.serialize(&mut ser)
        //     .context(error::JsonSerializationSnafu {
        //         what: "key".to_owned(),
        //     })?;

        Ok(digest(&SHA256, &keyval).as_ref().to_vec().into())
    }

    /// Verify a signature of an object made with this key.
    pub(super) fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        let (alg, public_key): (&dyn VerificationAlgorithm, untrusted::Input<'_>) = match self {
            Key::Ecdsa {
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                keyval,
                ..
            } => (
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                untrusted::Input::from(&keyval.public),
            ),
            Key::Ed25519 {
                scheme: Ed25519Scheme::Ed25519,
                keyval,
                ..
            } => (
                &ring::signature::ED25519,
                untrusted::Input::from(&keyval.public),
            ),
            Key::Rsa {
                scheme: RsaScheme::RsassaPssSha256,
                keyval,
                ..
            } => (
                &ring::signature::RSA_PSS_2048_8192_SHA256,
                untrusted::Input::from(&keyval.public),
            ),
        };

        alg.verify(
            public_key,
            untrusted::Input::from(msg),
            untrusted::Input::from(signature),
        )
        .is_ok()
    }
}

impl FromStr for Key {
    type Err = KeyParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(public) = serde_plain::from_str::<Decoded<RsaPem>>(s) {
            Ok(Key::Rsa {
                keyval: RsaKey {
                    public,
                    _extra: HashMap::new(),
                },
                scheme: RsaScheme::RsassaPssSha256,
                _extra: HashMap::new(),
            })
        } else if let Ok(public) = serde_plain::from_str::<Decoded<Hex>>(s) {
            if public.len() == ring::signature::ED25519_PUBLIC_KEY_LEN {
                Ok(Key::Ed25519 {
                    keyval: Ed25519Key {
                        public,
                        _extra: HashMap::new(),
                    },
                    scheme: Ed25519Scheme::Ed25519,
                    _extra: HashMap::new(),
                })
            } else {
                Err(KeyParseError(()))
            }
        } else if let Ok(public) = serde_plain::from_str::<Decoded<EcdsaFlex>>(s) {
            Ok(Key::Ecdsa {
                keyval: EcdsaKey {
                    public,
                    _extra: HashMap::new(),
                },
                scheme: EcdsaScheme::EcdsaSha2Nistp256,
                _extra: HashMap::new(),
            })
        } else {
            Err(KeyParseError(()))
        }
    }
}

/// An error object to be used when a key cannot be parsed.
#[derive(Debug, Clone, Copy)]
pub struct KeyParseError(());

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unrecognized or invalid public key")
    }
}

impl std::error::Error for KeyParseError {}
