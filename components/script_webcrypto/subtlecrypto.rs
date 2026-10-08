/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// mod aes_cbc_operation;
// mod aes_common;
// mod aes_ctr_operation;
// mod aes_gcm_operation;
// mod aes_kw_operation;
// mod aes_ocb_operation;
// mod argon2_operation;
// mod chacha20_poly1305_operation;
// mod cshake_operation;
// mod ec_common;
// mod ecdh_operation;
// mod ecdsa_operation;
// mod ed25519_operation;
// mod ed448_operation;
// mod hkdf_operation;
// mod hmac_operation;
// mod hybrid_kem_operation;
// mod kangarootwelve_operation;
// mod kmac_operation;
// mod ml_dsa_operation;
// mod ml_kem_operation;
// mod pbkdf2_operation;
// mod rsa_common;
// mod rsa_oaep_operation;
// mod rsa_pss_operation;
// mod rsassa_pkcs1_v1_5_operation;
// mod sha3_operation;
// mod sha_operation;
// mod turboshake_operation;
// mod x25519_operation;
// mod x448_operation;

use std::fmt::Display;
use std::marker::PhantomData;
use std::ptr;
use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use dom_struct::dom_struct;
use js::rooted;
use js::context::JSContext;
use js::conversions::{ConversionBehavior, ConversionResult, FromJSValConvertible, ToJSValConvertible};
use js::jsapi::{Heap, JSObject};
use js::jsval::{ObjectOrNullValue, UndefinedValue};
use js::realm::CurrentRealm;
use js::rust::wrappers2::{JS_NewObject, JS_ParseJSON};
use js::rust::{HandleObject, MutableHandleValue, Trace};
use js::typedarray::{ArrayBufferU8, HeapUint8Array};
use jstraceable_derive::JSTraceable;
use malloc_size_of_derive::MallocSizeOf;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_wrap};
use servo_constellation_traits::{
    SerializableAesKeyAlgorithm, SerializableAlgorithm, SerializableCShakeParams,
    SerializableDigestAlgorithm, SerializableEcKeyAlgorithm, SerializableHmacKeyAlgorithm,
    SerializableKangarooTwelveParams, SerializableKeyAlgorithm,
    SerializableKeyAlgorithmAndDerivatives, SerializableKmacKeyAlgorithm,
    SerializableRsaHashedKeyAlgorithm, SerializableTurboShakeParams,
};
use strum::{EnumString, IntoStaticStr, VariantArray};
use zeroize::Zeroizing;

use script_bindings::buffer_source::{create_buffer_source, get_buffer_source_copy};
use script_bindings::codegen::GenericBindings::CryptoKeyBinding::{
    CryptoKeyMethods, CryptoKeyPair, KeyType, KeyUsage
};
use script_bindings::codegen::GenericBindings::SubtleCryptoBinding::{
    Algorithm as AlgorithmWithDOMString, AlgorithmIdentifier, JsonWebKey, KeyFormat,
    SubtleCryptoMethods,
    Wrap as SubtleCryptoWrap,
};
use script_bindings::codegen::GenericUnionTypes::{
    ArrayBufferViewOrArrayBuffer
};
// use script_bindings::codegen::GenericUnionTypes::{
//     ArrayBufferViewOrArrayBufferOrJsonWebKey,
// };
use script_bindings::conversions::{
    StringificationBehavior, get_property,
};
use script_bindings::error::{Error, Fallible};
use script_bindings::refcounted::Trusted;
// use script_bindings::reflector::DomGlobal;
use script_bindings::root::DomRoot;
use script_bindings::str::{DOMString, serialize_jsval_to_json_utf8};
use script_bindings::trace::RootedTraceableBox;
use script_bindings::utils::set_dictionary_property;
use script_bindings::task;
use script_bindings::DomTypes;
use script_bindings::interfaces::PromiseHelpers;
use script_bindings::interfaces::StackRootPromiseHelpers;
use script_bindings::interfaces::HeapTracedPromiseHelpers;
use script_bindings::reflector::DomGlobalGeneric;

use crate::traits::Equivalence;

// Named elliptic curves
const NAMED_CURVE_P256: &str = "P-256";
const NAMED_CURVE_P384: &str = "P-384";
const NAMED_CURVE_P521: &str = "P-521";

static SUPPORTED_CURVES: &[&str] = &[NAMED_CURVE_P256, NAMED_CURVE_P384, NAMED_CURVE_P521];

#[derive(EnumString, VariantArray, IntoStaticStr, PartialEq, Clone, Copy, MallocSizeOf)]
enum CryptoAlgorithm {
    #[strum(serialize = "RSASSA-PKCS1-v1_5")]
    RsassaPkcs1V1_5,
    #[strum(serialize = "RSA-PSS")]
    RsaPss,
    #[strum(serialize = "RSA-OAEP")]
    RsaOaep,
    #[strum(serialize = "ECDSA")]
    Ecdsa,
    #[strum(serialize = "ECDH")]
    Ecdh,
    #[strum(serialize = "Ed25519")]
    Ed25519,
    #[strum(serialize = "X25519")]
    X25519,
    #[strum(serialize = "Ed448")]
    Ed448,
    #[strum(serialize = "X448")]
    X448,
    #[strum(serialize = "AES-CTR")]
    AesCtr,
    #[strum(serialize = "AES-CBC")]
    AesCbc,
    #[strum(serialize = "AES-GCM")]
    AesGcm,
    #[strum(serialize = "AES-KW")]
    AesKw,
    #[strum(serialize = "HMAC")]
    Hmac,
    #[strum(serialize = "SHA-1")]
    Sha1,
    #[strum(serialize = "SHA-256")]
    Sha256,
    #[strum(serialize = "SHA-384")]
    Sha384,
    #[strum(serialize = "SHA-512")]
    Sha512,
    #[strum(serialize = "HKDF")]
    Hkdf,
    #[strum(serialize = "PBKDF2")]
    Pbkdf2,
    #[strum(serialize = "ML-KEM-512")]
    MlKem512,
    #[strum(serialize = "ML-KEM-768")]
    MlKem768,
    #[strum(serialize = "ML-KEM-1024")]
    MlKem1024,
    #[strum(serialize = "MLKEM768-X25519")]
    MlKem768X25519,
    #[strum(serialize = "ML-DSA-44")]
    MlDsa44,
    #[strum(serialize = "ML-DSA-65")]
    MlDsa65,
    #[strum(serialize = "ML-DSA-87")]
    MlDsa87,
    #[strum(serialize = "AES-OCB")]
    AesOcb,
    #[strum(serialize = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
    #[strum(serialize = "SHA3-256")]
    Sha3_256,
    #[strum(serialize = "SHA3-384")]
    Sha3_384,
    #[strum(serialize = "SHA3-512")]
    Sha3_512,
    #[strum(serialize = "cSHAKE128")]
    CShake128,
    #[strum(serialize = "cSHAKE256")]
    CShake256,
    #[strum(serialize = "TurboSHAKE128")]
    TurboShake128,
    #[strum(serialize = "TurboSHAKE256")]
    TurboShake256,
    #[strum(serialize = "KT128")]
    Kt128,
    #[strum(serialize = "KT256")]
    Kt256,
    #[strum(serialize = "KMAC128")]
    Kmac128,
    #[strum(serialize = "KMAC256")]
    Kmac256,
    #[strum(serialize = "Argon2d")]
    Argon2D,
    #[strum(serialize = "Argon2i")]
    Argon2I,
    #[strum(serialize = "Argon2id")]
    Argon2ID,
}

impl CryptoAlgorithm {
    /// <https://w3c.github.io/webcrypto/#recognized-algorithm-name>
    fn as_str(&self) -> &'static str {
        (*self).into()
    }

    fn from_str_ignore_case(algorithm_name: &str) -> Fallible<CryptoAlgorithm> {
        Self::VARIANTS
            .iter()
            .find(|algorithm| algorithm.as_str().eq_ignore_ascii_case(algorithm_name))
            .cloned()
            .ok_or(Error::NotSupported(Some(format!(
                "Unsupported algorithm: {algorithm_name}"
            ))))
    }
}

/// <https://w3c.github.io/webcrypto/#subtlecrypto-interface>
#[dom_struct]
pub struct SubtleCrypto<D: DomTypes> {
    reflector_: Reflector,
    #[no_trace = "PhantomData does not exist"]
    phantom: PhantomData<D>,
}

impl<D> SubtleCrypto<D>
where
    D: Equivalence,
{
    fn new_inherited() -> SubtleCrypto<D> {
        SubtleCrypto {
            reflector_: Reflector::new(),
            phantom: PhantomData,
        }
    }

    pub fn new(cx: &mut JSContext, global: &D::GlobalScope) -> DomRoot<SubtleCrypto<D>> {
        reflect_dom_object_with_wrap::<D, _, _>(cx, Box::new(SubtleCrypto::new_inherited()), global, SubtleCryptoWrap::<D>)
    }
}

impl<D> SubtleCryptoMethods<D> for SubtleCrypto<D>
where
    D: DomTypes,
{
    /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-SubtleCrypto-method-supports>
    fn Supports(
        cx: &mut JSContext,
        _global: &D::GlobalScope,
        operation: DOMString,
        algorithm: AlgorithmIdentifier,
        length: Option<u32>,
    ) -> bool {
        todo!()
    }
}
