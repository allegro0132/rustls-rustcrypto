use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;

use self::ecdsa::{ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384};
use self::eddsa::ED25519;
use self::rsa::{
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
    ],
};

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;

/// Go 1.26 signature preference, including implemented P-521 verification.
/// Default provider behavior remains unchanged; callers opt in explicitly.
pub static GO_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
        ED25519, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
        RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ecdsa::ECDSA_P521_SHA512,
        ecdsa::ECDSA_P256_SHA512, ecdsa::ECDSA_P384_SHA512,
        ecdsa::ECDSA_P521_SHA256, ecdsa::ECDSA_P521_SHA384,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ecdsa::ECDSA_P521_SHA256]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ecdsa::ECDSA_P521_SHA384]),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ecdsa::ECDSA_P521_SHA512, ecdsa::ECDSA_P256_SHA512, ecdsa::ECDSA_P384_SHA512]),
    ],
};
