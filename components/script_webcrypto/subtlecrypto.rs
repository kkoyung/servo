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

// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-check-support-for-algorithm>
// pub(crate) fn check_support_for_algorithm(
//     cx: &mut JSContext,
//     mut operation: &str,
//     algorithm: &AlgorithmIdentifier,
//     length: Option<u32>,
// ) -> bool {
//     // Step 1. If op is "encapsulateKey" or "encapsulateBits", set op to "encapsulate".
//     if operation == "encapsulateKey" || operation == "encapsulateBits" {
//         operation = "encapsulate";
//     }
//
//     // Step 2. If op is "decapsulateKey" or "decapsulateBits", set op to "decapsulate".
//     if operation == "decapsulateKey" || operation == "decapsulateBits" {
//         operation = "decapsulate";
//     }
//
//     // Step 3. If op is "getPublicKey":
//     if operation == "getPublicKey" {
//         // Step 3.1. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg
//         // set to alg and op set to "exportKey".
//         // Step 3.2. If an error occurred, return false.
//         let Ok(normalized_algorithm) = normalize_algorithm::<ExportKeyOperation>(cx, algorithm)
//         else {
//             return false;
//         };
//
//         // Step 3.3. If the cryptographic algorithm identified by normalizedAlgorithm does not
//         // support deriving a public key from a private key, then return false.
//         // Step 3.4. Otherwise, return true.
//         //
//         // NOTE: We rely on [`normalize_algorithm`] to check whether the algorithm supports the
//         // getPublicKey operation.
//         return normalize_algorithm::<GetPublicKeyOperation>(
//             cx,
//             &AlgorithmIdentifier::String(DOMString::from_static(
//                 normalized_algorithm.name().as_str(),
//             )),
//         )
//         .is_ok();
//     }
//
//     // Step 4. Let normalizedAlgorithm be the result of normalizing an algorithm, with alg set to
//     // alg and op set to op.
//     // Step 5. If an error occurred:
//     //     Step 5.1. If op is "wrapKey", return the result of checking support for an algorithm
//     //     with op set to "encrypt" and alg set to alg.
//     //     Step 5.2. If op is "unwrapKey", return the result of checking support for an algorithm
//     //     with op set to "decrypt" and alg set to alg.
//     //     Step 5.3. Otherwise, return false.
//     // Step 6. Return the result of determining support from operation steps, with op set to op,
//     // normalizedAlgorithm set to normalizedAlgorithm, and length set to length.
//     match operation {
//         "encrypt" => {
//             normalize_and_determine_support::<EncryptOperation>(cx, operation, algorithm, length)
//         },
//         "decrypt" => {
//             normalize_and_determine_support::<DecryptOperation>(cx, operation, algorithm, length)
//         },
//         "sign" => {
//             normalize_and_determine_support::<SignOperation>(cx, operation, algorithm, length)
//         },
//         "verify" => {
//             normalize_and_determine_support::<VerifyOperation>(cx, operation, algorithm, length)
//         },
//         "digest" => {
//             normalize_and_determine_support::<DigestOperation>(cx, operation, algorithm, length)
//         },
//         "deriveBits" => {
//             normalize_and_determine_support::<DeriveBitsOperation>(cx, operation, algorithm, length)
//         },
//         "wrapKey" => {
//             normalize_and_determine_support::<WrapKeyOperation>(cx, operation, algorithm, length)
//         },
//         "unwrapKey" => {
//             normalize_and_determine_support::<UnwrapKeyOperation>(cx, operation, algorithm, length)
//         },
//         "generateKey" => normalize_and_determine_support::<GenerateKeyOperation>(
//             cx, operation, algorithm, length,
//         ),
//         "importKey" => {
//             normalize_and_determine_support::<ImportKeyOperation>(cx, operation, algorithm, length)
//         },
//         "exportKey" => {
//             normalize_and_determine_support::<ExportKeyOperation>(cx, operation, algorithm, length)
//         },
//         "get key length" => normalize_and_determine_support::<GetKeyLengthOperation>(
//             cx, operation, algorithm, length,
//         ),
//         "encapsulate" => normalize_and_determine_support::<EncapsulateOperation>(
//             cx, operation, algorithm, length,
//         ),
//         "decapsulate" => normalize_and_determine_support::<DecapsulateOperation>(
//             cx, operation, algorithm, length,
//         ),
//         _ => false,
//     }
// }
//
// /// Helper function for Step 4 - 6 of
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-check-support-for-algorithm>
// fn normalize_and_determine_support<T: Operation>(
//     cx: &mut JSContext,
//     op: &str,
//     algorithm: &AlgorithmIdentifier,
//     length: Option<u32>,
// ) -> bool {
//     if let Ok(normalized_algorithm) = normalize_algorithm::<T>(cx, algorithm) {
//         normalized_algorithm.determine_support_from_operation_steps(length)
//     } else {
//         match op {
//             "wrapKey" => check_support_for_algorithm(cx, "encrypt", algorithm, length),
//             "unwrapKey" => check_support_for_algorithm(cx, "decrypt", algorithm, length),
//             _ => false,
//         }
//     }
// }
//
// /// Alternative to std::convert::TryFrom, with `&mut js::context::JSContext`
// trait TryFromWithCxAndName<T>: Sized {
//     type Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         value: T,
//     ) -> Result<Self, Self::Error>;
// }
//
// /// Alternative to std::convert::TryInto, with `&mut js::context::JSContext`
// trait TryIntoWithCxAndName<T>: Sized {
//     type Error;
//
//     fn try_into_with_cx_and_name(
//         self,
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//     ) -> Result<T, Self::Error>;
// }
//
// impl<T, U> TryIntoWithCxAndName<U> for T
// where
//     U: TryFromWithCxAndName<T>,
// {
//     type Error = U::Error;
//
//     fn try_into_with_cx_and_name(
//         self,
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//     ) -> Result<U, Self::Error> {
//         U::try_from_with_cx_and_name(cx, algorithm_name, self)
//     }
// }
//
// // Custom binding types of WebIDL dictionary for WebCrypto
// //
// // In our implementation of WebCrypto API, we use custom binding types for the following WebIDL
// // dictionaries, instead of the binding types generated by `script_bindings`:
// //
// // - `KeyAlgorithm` and their derivatives
// // - `Algorithm` and their derivatives
// // - `EncapsulatedKey`
// // - `DecapsulatedKey`
// //
// // Based on the design of WebCrypto API, they frequently need to cross thread boundaries, but the
// // generated binding types for these dictionaries are not thread-safe. Therefore, we implement the
// // following thread-safe custom binding type for these dictionaries.
// //
// // There is one exception. The [`normalize_algorithm`] function still uses the generated binding
// // type for the `Algorithm` dictionary, as the custom binding type for `Algorithm` currently does
// // not accept arbitrary string in its `name` field.
//
// /// <https://w3c.github.io/webcrypto/#dfn-Algorithm>
// #[derive(Clone, MallocSizeOf)]
// struct Algorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for Algorithm {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         _cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         _object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(Algorithm {
//             name: algorithm_name,
//         })
//     }
// }
//
// impl TryFrom<SerializableAlgorithm> for Algorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableAlgorithm) -> Result<Self, Self::Error> {
//         Ok(Algorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//         })
//     }
// }
//
// impl From<&Algorithm> for SerializableAlgorithm {
//     fn from(value: &Algorithm) -> Self {
//         SerializableAlgorithm {
//             name: value.name.as_str().into(),
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-KeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct KeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
// }
//
// impl ToJSValConvertible for KeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of KeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableKeyAlgorithm> for KeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(KeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//         })
//     }
// }
//
// impl From<&KeyAlgorithm> for SerializableKeyAlgorithm {
//     fn from(value: &KeyAlgorithm) -> Self {
//         SerializableKeyAlgorithm {
//             name: value.name.as_str().into(),
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedKeyGenParams>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct RsaHashedKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaKeyGenParams-modulusLength>
//     modulus_length: u32,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaKeyGenParams-publicExponent>
//     public_exponent: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedKeyGenParams-hash>
//     hash: DigestAlgorithm,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for RsaHashedKeyGenParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(RsaHashedKeyGenParams {
//             name: algorithm_name,
//             modulus_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"modulusLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             public_exponent: get_required_parameter_in_box::<HeapUint8Array>(
//                 cx,
//                 object,
//                 c"publicExponent",
//                 (),
//             )?
//             .to_vec()
//             .unwrap_or_default(),
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//         })
//     }
// }
//
// impl RsaHashedKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dfn-validate-rsa-key-generation-parameters>
//     fn validate_parameters(&self) -> Result<(), Error> {
//         // Step 1. Let modulusLength be the modulusLength member of normalizedAlgorithm.
//         let modulus_length = self.modulus_length;
//
//         // Step 2. Let publicExponent be the result of converting the publicExponent member of
//         // normalizedAlgorithm to a non-negative integer.
//         let public_exponent = &self.public_exponent;
//
//         // Step 3. If modulusLength is less than 4, or if publicExponent is less than 3, is even, or
//         // is greater than or equal to 2^modulusLength - 1, then throw an OperationError.
//         let is_less_than_3 = |public_exponent: &[u8]| {
//             let mut byte_iterator = public_exponent.iter().skip_while(|byte| **byte == 0);
//             byte_iterator.next().is_none_or(|byte| *byte < 3) && byte_iterator.count() == 0
//         };
//         let is_even =
//             |public_exponent: &[u8]| public_exponent.last().is_none_or(|byte| byte % 2 == 0);
//         let upper_bound_first_byte = (1u8 << (modulus_length % 8)).wrapping_sub(1);
//         let upper_bound_length_in_bytes = modulus_length.div_ceil(8) as usize;
//         let is_greater_than_upper_bound = |public_exponent: &[u8]| {
//             let mut byte_iterator = public_exponent.iter().skip_while(|byte| **byte == 0);
//             byte_iterator
//                 .next()
//                 .is_some_and(|byte| *byte > upper_bound_first_byte) &&
//                 byte_iterator.count() + 1 >= upper_bound_length_in_bytes
//         };
//         let is_equal_to_upper_bound = |public_exponent: &[u8]| {
//             let mut byte_iterator = public_exponent.iter().skip_while(|byte| **byte == 0);
//             byte_iterator
//                 .next()
//                 .is_some_and(|byte| *byte == upper_bound_first_byte) &&
//                 byte_iterator.clone().all(|byte| *byte == 255) &&
//                 byte_iterator.count() + 1 == upper_bound_length_in_bytes
//         };
//         if modulus_length < 4 ||
//             is_less_than_3(public_exponent) ||
//             is_even(public_exponent) ||
//             is_greater_than_upper_bound(public_exponent) ||
//             is_equal_to_upper_bound(public_exponent)
//         {
//             return Err(Error::Operation(Some(
//                 "Invalid RsaHashedKeyGenParams".into(),
//             )));
//         }
//
//         Ok(())
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedKeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct RsaHashedKeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaKeyAlgorithm-modulusLength>
//     modulus_length: u32,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaKeyAlgorithm-publicExponent>
//     public_exponent: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedKeyAlgorithm-hash>
//     hash: DigestAlgorithm,
// }
//
// impl ToJSValConvertible for RsaHashedKeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of RsaHashedKeyAlgorithm");
//
//         rooted!(&in(cx) let mut modulus_length_js = UndefinedValue());
//         self.modulus_length
//             .to_jsval(cx, modulus_length_js.handle_mut());
//         set_dictionary_property(
//             cx,
//             object.handle(),
//             c"modulusLength",
//             modulus_length_js.handle(),
//         )
//         .expect("Failed to set modulusLength property of RsaHashedKeyAlgorithm");
//
//         rooted!(&in(cx) let mut public_exponent_js = UndefinedValue());
//         rooted!(&in(cx) let mut public_exponent_js_object = ptr::null_mut::<JSObject>());
//         let public_exponent = create_buffer_source::<ArrayBufferU8>(
//             cx,
//             &self.public_exponent,
//             public_exponent_js_object.handle_mut(),
//         )
//         .expect("Failed to convert publicExponent to Uint8Array");
//         public_exponent.to_jsval(cx, public_exponent_js.handle_mut());
//         set_dictionary_property(
//             cx,
//             object.handle(),
//             c"publicExponent",
//             public_exponent_js.handle(),
//         )
//         .expect("Failed to set publicExponent property of RsaHashedKeyAlgorithm");
//
//         rooted!(&in(cx) let mut hash_js = UndefinedValue());
//         let hash = KeyAlgorithm {
//             name: self.hash.name(),
//         };
//         hash.to_jsval(cx, hash_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"hash", hash_js.handle())
//             .expect("Failed to set hash property of RsaHashedKeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableRsaHashedKeyAlgorithm> for RsaHashedKeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableRsaHashedKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(RsaHashedKeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             modulus_length: value.modulus_length,
//             public_exponent: value.public_exponent,
//             hash: value.hash.try_into()?,
//         })
//     }
// }
//
// impl From<&RsaHashedKeyAlgorithm> for SerializableRsaHashedKeyAlgorithm {
//     fn from(value: &RsaHashedKeyAlgorithm) -> Self {
//         SerializableRsaHashedKeyAlgorithm {
//             name: value.name.as_str().into(),
//             modulus_length: value.modulus_length,
//             public_exponent: value.public_exponent.clone(),
//             hash: (&value.hash).into(),
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedImportParams>
// #[derive(Clone, MallocSizeOf)]
// struct RsaHashedImportParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaHashedImportParams-hash>
//     hash: DigestAlgorithm,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for RsaHashedImportParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(RsaHashedImportParams {
//             name: algorithm_name,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-RsaPssParams>
// #[derive(Clone, MallocSizeOf)]
// struct RsaPssParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaPssParams-saltLength>
//     salt_length: u32,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for RsaPssParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Result<Self, Self::Error> {
//         Ok(RsaPssParams {
//             name: algorithm_name,
//             salt_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"saltLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-RsaOaepParams>
// #[derive(Clone, MallocSizeOf)]
// struct RsaOaepParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-RsaOaepParams-label>
//     label: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for RsaOaepParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(RsaOaepParams {
//             name: algorithm_name,
//             label: get_optional_buffer_source(cx, object, c"label")?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-EcdsaParams>
// #[derive(Clone, MallocSizeOf)]
// struct EcdsaParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-EcdsaParams-hash>
//     hash: DigestAlgorithm,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for EcdsaParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(EcdsaParams {
//             name: algorithm_name,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-EcKeyGenParams>
// #[derive(Clone, MallocSizeOf)]
// struct EcKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-EcKeyGenParams-namedCurve>
//     named_curve: String,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for EcKeyGenParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(EcKeyGenParams {
//             name: algorithm_name,
//             named_curve: String::from(get_required_parameter::<DOMString>(
//                 cx,
//                 object,
//                 c"namedCurve",
//                 StringificationBehavior::Default,
//             )?),
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-EcKeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct EcKeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-EcKeyAlgorithm-namedCurve>
//     named_curve: String,
// }
//
// impl ToJSValConvertible for EcKeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of EcKeyAlgorithm");
//
//         rooted!(&in(cx) let mut named_curve_js = UndefinedValue());
//         self.named_curve.to_jsval(cx, named_curve_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"namedCurve", named_curve_js.handle())
//             .expect("Failed to set namedCurve property of EcKeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableEcKeyAlgorithm> for EcKeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableEcKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(EcKeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             named_curve: value.named_curve,
//         })
//     }
// }
//
// impl From<&EcKeyAlgorithm> for SerializableEcKeyAlgorithm {
//     fn from(value: &EcKeyAlgorithm) -> Self {
//         SerializableEcKeyAlgorithm {
//             name: value.name.as_str().into(),
//             named_curve: value.named_curve.clone(),
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-EcKeyImportParams>
// #[derive(Clone, MallocSizeOf)]
// struct EcKeyImportParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-EcKeyImportParams-namedCurve>
//     named_curve: String,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for EcKeyImportParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(EcKeyImportParams {
//             name: algorithm_name,
//             named_curve: String::from(get_required_parameter::<DOMString>(
//                 cx,
//                 object,
//                 c"namedCurve",
//                 StringificationBehavior::Default,
//             )?),
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-EcdhKeyDeriveParams>
// #[derive(Clone, MallocSizeOf)]
// struct EcdhKeyDeriveParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-EcdhKeyDeriveParams-public>
//     public: Trusted<CryptoKey>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for EcdhKeyDeriveParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let public = get_required_parameter::<DomRoot<CryptoKey>>(cx, object, c"public", ())?;
//
//         Ok(EcdhKeyDeriveParams {
//             name: algorithm_name,
//             public: Trusted::new(&public),
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesCtrParams>
// #[derive(Clone, MallocSizeOf)]
// struct AesCtrParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesCtrParams-counter>
//     counter: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesCtrParams-length>
//     length: u8,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AesCtrParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AesCtrParams {
//             name: algorithm_name,
//             counter: get_required_buffer_source(cx, object, c"counter")?,
//             length: get_required_parameter(
//                 cx,
//                 object,
//                 c"length",
//                 ConversionBehavior::EnforceRange,
//             )?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesKeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct AesKeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesKeyAlgorithm-length>
//     length: u16,
// }
//
// impl ToJSValConvertible for AesKeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of AesKeyAlgorithm");
//
//         rooted!(&in(cx) let mut length_js = UndefinedValue());
//         self.length.to_jsval(cx, length_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"length", length_js.handle())
//             .expect("Failed to set length property of AesKeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableAesKeyAlgorithm> for AesKeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableAesKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(AesKeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             length: value.length,
//         })
//     }
// }
//
// impl From<&AesKeyAlgorithm> for SerializableAesKeyAlgorithm {
//     fn from(value: &AesKeyAlgorithm) -> Self {
//         SerializableAesKeyAlgorithm {
//             name: value.name.as_str().into(),
//             length: value.length,
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesKeyGenParams>
// #[derive(Clone, MallocSizeOf)]
// struct AesKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesKeyGenParams-length>
//     length: u16,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AesKeyGenParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AesKeyGenParams {
//             name: algorithm_name,
//             length: get_required_parameter(
//                 cx,
//                 object,
//                 c"length",
//                 ConversionBehavior::EnforceRange,
//             )?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesDerivedKeyParams>
// #[derive(Clone, MallocSizeOf)]
// struct AesDerivedKeyParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesDerivedKeyParams-length>
//     length: u16,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AesDerivedKeyParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AesDerivedKeyParams {
//             name: algorithm_name,
//             length: get_required_parameter(
//                 cx,
//                 object,
//                 c"length",
//                 ConversionBehavior::EnforceRange,
//             )?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesCbcParams>
// #[derive(Clone, MallocSizeOf)]
// struct AesCbcParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesCbcParams-iv>
//     iv: Vec<u8>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AesCbcParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AesCbcParams {
//             name: algorithm_name,
//             iv: get_required_buffer_source(cx, object, c"iv")?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-AesGcmParams>
// #[derive(Clone, MallocSizeOf)]
// struct AesGcmParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesGcmParams-iv>
//     iv: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesGcmParams-additionalData>
//     additional_data: Option<Vec<u8>>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-AesGcmParams-tagLength>
//     tag_length: Option<u8>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AesGcmParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AesGcmParams {
//             name: algorithm_name,
//             iv: get_required_buffer_source(cx, object, c"iv")?,
//             additional_data: get_optional_buffer_source(cx, object, c"additionalData")?,
//             tag_length: get_property(cx, object, c"tagLength", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-HmacImportParams>
// #[derive(Clone, MallocSizeOf)]
// struct HmacImportParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacImportParams-hash>
//     hash: DigestAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacImportParams-length>
//     length: Option<u32>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for HmacImportParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(HmacImportParams {
//             name: algorithm_name,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//             length: get_property(cx, object, c"length", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct HmacKeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyAlgorithm-hash>
//     hash: DigestAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyGenParams-length>
//     length: u32,
// }
//
// impl ToJSValConvertible for HmacKeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of HmacKeyAlgorithm");
//
//         rooted!(&in(cx) let mut hash_js = UndefinedValue());
//         let hash = KeyAlgorithm {
//             name: self.hash.name(),
//         };
//         hash.to_jsval(cx, hash_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"hash", hash_js.handle())
//             .expect("Failed to set hash property of HmacKeyAlgorithm");
//
//         rooted!(&in(cx) let mut length_js = UndefinedValue());
//         self.length.to_jsval(cx, length_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"length", length_js.handle())
//             .expect("Failed to set length property of HmacKeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableHmacKeyAlgorithm> for HmacKeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableHmacKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(HmacKeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             hash: value.hash.try_into()?,
//             length: value.length,
//         })
//     }
// }
//
// impl From<&HmacKeyAlgorithm> for SerializableHmacKeyAlgorithm {
//     fn from(value: &HmacKeyAlgorithm) -> Self {
//         SerializableHmacKeyAlgorithm {
//             name: value.name.as_str().into(),
//             hash: (&value.hash).into(),
//             length: value.length,
//         }
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyGenParams>
// #[derive(Clone, MallocSizeOf)]
// struct HmacKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyGenParams-hash>
//     hash: DigestAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HmacKeyGenParams-length>
//     length: Option<u32>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for HmacKeyGenParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(HmacKeyGenParams {
//             name: algorithm_name,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//             length: get_property(cx, object, c"length", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-HkdfParams>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct HkdfParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HkdfParams-hash>
//     hash: DigestAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HkdfParams-salt>
//     salt: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-HkdfParams-info>
//     info: Vec<u8>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for HkdfParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(HkdfParams {
//             name: algorithm_name,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//             salt: get_required_buffer_source(cx, object, c"salt")?,
//             info: get_required_buffer_source(cx, object, c"info")?,
//         })
//     }
// }
//
// /// <https://w3c.github.io/webcrypto/#dfn-Pbkdf2Params>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct Pbkdf2Params {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-Pbkdf2Params-salt>
//     salt: Vec<u8>,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-Pbkdf2Params-iterations>
//     iterations: u32,
//
//     /// <https://w3c.github.io/webcrypto/#dfn-Pbkdf2Params-hash>
//     hash: DigestAlgorithm,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for Pbkdf2Params {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         let hash = get_required_parameter(cx, object, c"hash", ())?;
//
//         Ok(Pbkdf2Params {
//             name: algorithm_name,
//             salt: get_required_buffer_source(cx, object, c"salt")?,
//             iterations: get_required_parameter(
//                 cx,
//                 object,
//                 c"iterations",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             hash: normalize_algorithm::<DigestOperation>(cx, &hash)?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-ContextParams>
// #[derive(Clone, MallocSizeOf)]
// struct ContextParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-ContextParams-context>
//     context: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for ContextParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(ContextParams {
//             name: algorithm_name,
//             context: get_optional_buffer_source(cx, object, c"context")?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-AeadParams>
// #[derive(Clone, MallocSizeOf)]
// struct AeadParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-AeadParams-iv>
//     iv: Vec<u8>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-AeadParams-additionalData>
//     additional_data: Option<Vec<u8>>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-AeadParams-tagLength>
//     tag_length: Option<u8>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for AeadParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(AeadParams {
//             name: algorithm_name,
//             iv: get_required_buffer_source(cx, object, c"iv")?,
//             additional_data: get_optional_buffer_source(cx, object, c"additionalData")?,
//             tag_length: get_property(cx, object, c"tagLength", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-CShakeParams>
// #[derive(Clone, MallocSizeOf)]
// struct CShakeParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-CShakeParams-outputLength>
//     output_length: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-CShakeParams-functionName>
//     function_name: Option<Vec<u8>>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-CShakeParams-customization>
//     customization: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for CShakeParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(CShakeParams {
//             name: algorithm_name,
//             output_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"outputLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             function_name: get_optional_buffer_source(cx, object, c"functionName")?,
//             customization: get_optional_buffer_source(cx, object, c"customization")?,
//         })
//     }
// }
//
// impl TryFrom<SerializableCShakeParams> for CShakeParams {
//     type Error = ();
//
//     fn try_from(value: SerializableCShakeParams) -> Result<Self, Self::Error> {
//         Ok(CShakeParams {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             output_length: value.output_length,
//             function_name: value.function_name,
//             customization: value.customization,
//         })
//     }
// }
//
// impl From<&CShakeParams> for SerializableCShakeParams {
//     fn from(value: &CShakeParams) -> Self {
//         SerializableCShakeParams {
//             name: value.name.as_str().into(),
//             output_length: value.output_length,
//             function_name: value.function_name.clone(),
//             customization: value.customization.clone(),
//         }
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-TurboShakeParams>
// #[derive(Clone, MallocSizeOf)]
// struct TurboShakeParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-TurboShakeParams-outputLength>
//     output_length: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-TurboShakeParams-domainSeparation>
//     domain_separation: Option<u8>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for TurboShakeParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(TurboShakeParams {
//             name: algorithm_name,
//             output_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"outputLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             domain_separation: get_property(
//                 cx,
//                 object,
//                 c"domainSeparation",
//                 ConversionBehavior::EnforceRange,
//             )?,
//         })
//     }
// }
//
// impl TryFrom<SerializableTurboShakeParams> for TurboShakeParams {
//     type Error = ();
//
//     fn try_from(value: SerializableTurboShakeParams) -> Result<Self, Self::Error> {
//         Ok(TurboShakeParams {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             output_length: value.output_length,
//             domain_separation: value.domain_separation,
//         })
//     }
// }
//
// impl From<&TurboShakeParams> for SerializableTurboShakeParams {
//     fn from(value: &TurboShakeParams) -> Self {
//         SerializableTurboShakeParams {
//             name: value.name.as_str().into(),
//             output_length: value.output_length,
//             domain_separation: value.domain_separation,
//         }
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KangarooTwelveParams>
// #[derive(Clone, MallocSizeOf)]
// struct KangarooTwelveParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KangarooTwelveParams-outputLength>
//     output_length: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KangarooTwelveParams-customization>
//     customization: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for KangarooTwelveParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(KangarooTwelveParams {
//             name: algorithm_name,
//             output_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"outputLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             customization: get_optional_buffer_source(cx, object, c"customization")?,
//         })
//     }
// }
//
// impl TryFrom<SerializableKangarooTwelveParams> for KangarooTwelveParams {
//     type Error = ();
//
//     fn try_from(value: SerializableKangarooTwelveParams) -> Result<Self, Self::Error> {
//         Ok(KangarooTwelveParams {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             output_length: value.output_length,
//             customization: value.customization,
//         })
//     }
// }
//
// impl From<&KangarooTwelveParams> for SerializableKangarooTwelveParams {
//     fn from(value: &KangarooTwelveParams) -> Self {
//         SerializableKangarooTwelveParams {
//             name: value.name.as_str().into(),
//             output_length: value.output_length,
//             customization: value.customization.clone(),
//         }
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacKeyGenParams>
// #[derive(Clone, MallocSizeOf)]
// struct KmacKeyGenParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacKeyGenParams-length>
//     length: Option<u32>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for KmacKeyGenParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Result<Self, Self::Error> {
//         Ok(KmacKeyGenParams {
//             name: algorithm_name,
//             length: get_property(cx, object, c"length", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacImportParams>
// #[derive(Clone, MallocSizeOf)]
// struct KmacImportParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacImportParams-length>
//     length: Option<u32>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for KmacImportParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Result<Self, Self::Error> {
//         Ok(KmacImportParams {
//             name: algorithm_name,
//             length: get_property(cx, object, c"length", ConversionBehavior::EnforceRange)?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacKeyAlgorithm>
// #[derive(Clone, MallocSizeOf)]
// pub(crate) struct KmacKeyAlgorithm {
//     /// <https://w3c.github.io/webcrypto/#dom-keyalgorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacKeyAlgorithm-length>
//     length: u32,
// }
//
// impl ToJSValConvertible for KmacKeyAlgorithm {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut name_js = UndefinedValue());
//         self.name.as_str().to_jsval(cx, name_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"name", name_js.handle())
//             .expect("Failed to set name property of KmacKeyAlgorithm");
//
//         rooted!(&in(cx) let mut length_js = UndefinedValue());
//         self.length.to_jsval(cx, length_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"length", length_js.handle())
//             .expect("Failed to set length property of KmacKeyAlgorithm");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// impl TryFrom<SerializableKmacKeyAlgorithm> for KmacKeyAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableKmacKeyAlgorithm) -> Result<Self, Self::Error> {
//         Ok(KmacKeyAlgorithm {
//             name: CryptoAlgorithm::from_str(&value.name).map_err(|_| ())?,
//             length: value.length,
//         })
//     }
// }
//
// impl From<&KmacKeyAlgorithm> for SerializableKmacKeyAlgorithm {
//     fn from(value: &KmacKeyAlgorithm) -> Self {
//         SerializableKmacKeyAlgorithm {
//             name: value.name.as_str().into(),
//             length: value.length,
//         }
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacParams>
// struct KmacParams {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacParams-outputLength>
//     output_length: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-KmacParams-customization>
//     customization: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for KmacParams {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(KmacParams {
//             name: algorithm_name,
//             output_length: get_required_parameter(
//                 cx,
//                 object,
//                 c"outputLength",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             customization: get_optional_buffer_source(cx, object, c"customization")?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params>
// #[derive(Clone, MallocSizeOf)]
// struct Argon2Params {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-nonce>
//     nonce: Vec<u8>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-parallelism>
//     parallelism: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-memory>
//     memory: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-passes>
//     passes: u32,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-version>
//     version: Option<u8>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-secretValue>
//     secret_value: Option<Vec<u8>>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-Argon2Params-associatedData>
//     associated_data: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for Argon2Params {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(Argon2Params {
//             name: algorithm_name,
//             nonce: get_required_buffer_source(cx, object, c"nonce")?,
//             parallelism: get_required_parameter(
//                 cx,
//                 object,
//                 c"parallelism",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             memory: get_required_parameter(
//                 cx,
//                 object,
//                 c"memory",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             passes: get_required_parameter(
//                 cx,
//                 object,
//                 c"passes",
//                 ConversionBehavior::EnforceRange,
//             )?,
//             version: get_property(cx, object, c"version", ConversionBehavior::EnforceRange)?,
//             secret_value: get_optional_buffer_source(cx, object, c"secretValue")?,
//             associated_data: get_optional_buffer_source(cx, object, c"associatedData")?,
//         })
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedKey>
// struct EncapsulatedKey {
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedKey-sharedKey>
//     shared_key: Option<Trusted<CryptoKey>>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedKey-ciphertext>
//     ciphertext: Option<Vec<u8>>,
// }
//
// impl ToJSValConvertible for EncapsulatedKey {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut shared_key_js = UndefinedValue());
//         self.shared_key
//             .as_ref()
//             .map(|shared_key| shared_key.root())
//             .to_jsval(cx, shared_key_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"sharedKey", shared_key_js.handle())
//             .expect("Failed to set sharedKey property of EncapsulatedKey");
//
//         rooted!(&in(cx) let mut ciphertext_js = UndefinedValue());
//         self.ciphertext
//             .as_ref()
//             .map(|ciphertext| {
//                 rooted!(&in(cx) let mut ciphertext_js_object = ptr::null_mut::<JSObject>());
//                 create_buffer_source::<ArrayBufferU8>(
//                     cx,
//                     ciphertext,
//                     ciphertext_js_object.handle_mut(),
//                 )
//                 .expect("Failed to convert ciphertext to ArrayBufferU8")
//             })
//             .to_jsval(cx, ciphertext_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"ciphertext", ciphertext_js.handle())
//             .expect("Failed to set ciphertext property of EncapsulatedKey");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedBits>
// struct EncapsulatedBits {
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedBits-sharedKey>
//     shared_key: Option<Zeroizing<Vec<u8>>>,
//
//     /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-EncapsulatedBits-ciphertext>
//     ciphertext: Option<Vec<u8>>,
// }
//
// impl ToJSValConvertible for EncapsulatedBits {
//     #[expect(unsafe_code)]
//     fn to_jsval(&self, cx: &mut JSContext, mut rval: MutableHandleValue) {
//         rooted!(&in(cx) let mut object = unsafe { JS_NewObject(cx, ptr::null()) });
//
//         rooted!(&in(cx) let mut shared_key_js = UndefinedValue());
//         self.shared_key
//             .as_ref()
//             .map(|shared_key| {
//                 rooted!(&in(cx) let mut shared_key_js_object = ptr::null_mut::<JSObject>());
//                 create_buffer_source::<ArrayBufferU8>(
//                     cx,
//                     shared_key,
//                     shared_key_js_object.handle_mut(),
//                 )
//                 .expect("Failed to convert shared_key to ArrayBufferU8")
//             })
//             .to_jsval(cx, shared_key_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"sharedKey", shared_key_js.handle())
//             .expect("Failed to set sharedKey property of EncapsulatedBits");
//
//         rooted!(&in(cx) let mut ciphertext_js = UndefinedValue());
//         self.ciphertext
//             .as_ref()
//             .map(|ciphertext| {
//                 rooted!(&in(cx) let mut ciphertext_js_object = ptr::null_mut::<JSObject>());
//                 create_buffer_source::<ArrayBufferU8>(
//                     cx,
//                     ciphertext,
//                     ciphertext_js_object.handle_mut(),
//                 )
//                 .expect("Failed to convert ciphertext to ArrayBufferU8")
//             })
//             .to_jsval(cx, ciphertext_js.handle_mut());
//         set_dictionary_property(cx, object.handle(), c"ciphertext", ciphertext_js.handle())
//             .expect("Failed to set ciphertext property of EncapsulatedBits");
//
//         rval.set(ObjectOrNullValue(object.get()));
//     }
// }
//
// /// <https://wicg.github.io/webcrypto-secure-curves/#dfn-Ed448Params>
// #[derive(Clone, MallocSizeOf)]
// struct SubtleEd448Params {
//     /// <https://w3c.github.io/webcrypto/#dom-algorithm-name>
//     name: CryptoAlgorithm,
//
//     /// <https://wicg.github.io/webcrypto-secure-curves/#dfn-Ed448Params-context>
//     context: Option<Vec<u8>>,
// }
//
// impl<'a> TryFromWithCxAndName<HandleObject<'a>> for SubtleEd448Params {
//     type Error = Error;
//
//     fn try_from_with_cx_and_name(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject<'a>,
//     ) -> Result<Self, Self::Error> {
//         Ok(SubtleEd448Params {
//             name: algorithm_name,
//             context: get_optional_buffer_source(cx, object, c"context")?,
//         })
//     }
// }

/// Helper to retrieve a required paramter from WebIDL dictionary.
fn get_required_parameter<T: FromJSValConvertible>(
    cx: &mut JSContext,
    object: HandleObject,
    parameter: &std::ffi::CStr,
    option: T::Config,
) -> Fallible<T> {
    get_property::<T>(cx, object, parameter, option)?
        .ok_or(Error::Type(c"Missing required parameter".into()))
}

/// Helper to retrieve a required paramter, in RootedTraceableBox, from WebIDL dictionary.
fn get_required_parameter_in_box<T: FromJSValConvertible + Trace>(
    cx: &mut JSContext,
    object: HandleObject,
    parameter: &std::ffi::CStr,
    option: T::Config,
) -> Fallible<RootedTraceableBox<T>> {
    get_property::<T>(cx, object, parameter, option)?
        .map(RootedTraceableBox::new)
        .ok_or(Error::Type(c"Missing required parameter".into()))
}

/// Helper to retrieve an optional paramter in BufferSource from WebIDL dictionary, and get a copy
/// of the bytes held by the buffer source according to
/// <https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy>
fn get_optional_buffer_source(
    cx: &mut JSContext,
    object: HandleObject,
    parameter: &std::ffi::CStr,
) -> Fallible<Option<Vec<u8>>> {
    let buffer_source = get_property::<ArrayBufferViewOrArrayBuffer>(cx, object, parameter, ())?;
    Ok(buffer_source
        .as_ref()
        .map(|buffer| get_buffer_source_copy(buffer.into())))
}

/// Helper to retrieve a required paramter in BufferSource from WebIDL dictionary, and get a copy
/// of the bytes held by the buffer source according to
/// <https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy>
fn get_required_buffer_source(
    cx: &mut JSContext,
    object: HandleObject,
    parameter: &std::ffi::CStr,
) -> Fallible<Vec<u8>> {
    get_optional_buffer_source(cx, object, parameter)?
        .ok_or(Error::Type(c"Missing required parameter".into()))
}

// /// The returned type of the successful export key operation. `Bytes` should be used when the key
// /// is exported in "raw", "spki" or "pkcs8" format. `Jwk` should be used when the key is exported
// /// in "jwk" format.
// enum ExportedKey {
//     Bytes(Zeroizing<Vec<u8>>),
//     Jwk(Box<JsonWebKey>),
// }
//
// impl ExportedKey {
//     fn new_bytes(bytes: Vec<u8>) -> ExportedKey {
//         ExportedKey::Bytes(Zeroizing::new(bytes))
//     }
//
//     fn new_jwk(jwk: JsonWebKey) -> ExportedKey {
//         ExportedKey::Jwk(Box::new(jwk))
//     }
// }
//
// /// Union type of KeyAlgorithm and IDL dictionary types derived from it. Note that we actually use
// /// our "subtle" structs of the corresponding IDL dictionary types so that they can be easily
// /// passed to another threads.
// #[derive(Clone, MallocSizeOf)]
// #[expect(clippy::enum_variant_names)]
// pub(crate) enum KeyAlgorithmAndDerivatives {
//     KeyAlgorithm(KeyAlgorithm),
//     RsaHashedKeyAlgorithm(RsaHashedKeyAlgorithm),
//     EcKeyAlgorithm(EcKeyAlgorithm),
//     AesKeyAlgorithm(AesKeyAlgorithm),
//     HmacKeyAlgorithm(HmacKeyAlgorithm),
//     KmacKeyAlgorithm(KmacKeyAlgorithm),
// }
//
// impl KeyAlgorithmAndDerivatives {
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             KeyAlgorithmAndDerivatives::KeyAlgorithm(algorithm) => algorithm.name,
//             KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm) => algorithm.name,
//             KeyAlgorithmAndDerivatives::EcKeyAlgorithm(algorithm) => algorithm.name,
//             KeyAlgorithmAndDerivatives::AesKeyAlgorithm(algorithm) => algorithm.name,
//             KeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algorithm) => algorithm.name,
//             KeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algorithm) => algorithm.name,
//         }
//     }
// }
//
// impl ToJSValConvertible for KeyAlgorithmAndDerivatives {
//     fn to_jsval(&self, cx: &mut JSContext, rval: MutableHandleValue) {
//         match self {
//             KeyAlgorithmAndDerivatives::KeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//             KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//             KeyAlgorithmAndDerivatives::EcKeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//             KeyAlgorithmAndDerivatives::AesKeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//             KeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//             KeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algo) => algo.to_jsval(cx, rval),
//         }
//     }
// }
//
// impl TryFrom<SerializableKeyAlgorithmAndDerivatives> for KeyAlgorithmAndDerivatives {
//     type Error = ();
//
//     fn try_from(value: SerializableKeyAlgorithmAndDerivatives) -> Result<Self, Self::Error> {
//         match value {
//             SerializableKeyAlgorithmAndDerivatives::KeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::KeyAlgorithm(algorithm.try_into()?),
//             ),
//             SerializableKeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm.try_into()?),
//             ),
//             SerializableKeyAlgorithmAndDerivatives::EcKeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::EcKeyAlgorithm(algorithm.try_into()?),
//             ),
//             SerializableKeyAlgorithmAndDerivatives::AesKeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::AesKeyAlgorithm(algorithm.try_into()?),
//             ),
//             SerializableKeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algorithm.try_into()?),
//             ),
//             SerializableKeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algorithm) => Ok(
//                 KeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algorithm.try_into()?),
//             ),
//         }
//     }
// }
//
// impl From<&KeyAlgorithmAndDerivatives> for SerializableKeyAlgorithmAndDerivatives {
//     fn from(value: &KeyAlgorithmAndDerivatives) -> Self {
//         match value {
//             KeyAlgorithmAndDerivatives::KeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::KeyAlgorithm(algorithm.into())
//             },
//             KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm.into())
//             },
//             KeyAlgorithmAndDerivatives::EcKeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::EcKeyAlgorithm(algorithm.into())
//             },
//             KeyAlgorithmAndDerivatives::AesKeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::AesKeyAlgorithm(algorithm.into())
//             },
//             KeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::HmacKeyAlgorithm(algorithm.into())
//             },
//             KeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algorithm) => {
//                 SerializableKeyAlgorithmAndDerivatives::KmacKeyAlgorithm(algorithm.into())
//             },
//         }
//     }
// }
//
// #[derive(Clone, Copy)]
// enum JwkStringField {
//     X,
//     Y,
//     D,
//     N,
//     E,
//     P,
//     Q,
//     DP,
//     DQ,
//     QI,
//     K,
//     Priv,
//     Pub,
// }
//
// impl Display for JwkStringField {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         let field_name = match self {
//             JwkStringField::X => "x",
//             JwkStringField::Y => "y",
//             JwkStringField::D => "d",
//             JwkStringField::N => "n",
//             JwkStringField::E => "e",
//             JwkStringField::P => "q",
//             JwkStringField::Q => "q",
//             JwkStringField::DP => "dp",
//             JwkStringField::DQ => "dq",
//             JwkStringField::QI => "qi",
//             JwkStringField::K => "k",
//             JwkStringField::Priv => "priv",
//             JwkStringField::Pub => "pub",
//         };
//         write!(f, "{}", field_name)
//     }
// }
//
// trait JsonWebKeyExt {
//     fn parse(cx: &mut JSContext, data: &[u8]) -> Result<JsonWebKey, Error>;
//     fn stringify(&self, cx: &mut JSContext) -> Result<Zeroizing<DOMString>, Error>;
//     fn get_usages_from_key_ops(&self) -> Result<Vec<KeyUsage>, Error>;
//     fn check_key_ops(&self, specified_usages: &[KeyUsage]) -> Result<(), Error>;
//     fn set_key_ops(&mut self, usages: &[KeyUsage]);
//     fn encode_string_field(&mut self, field: JwkStringField, data: &[u8]);
//     fn decode_optional_string_field(
//         &self,
//         field: JwkStringField,
//     ) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;
//     fn decode_required_string_field(
//         &self,
//         field: JwkStringField,
//     ) -> Result<Zeroizing<Vec<u8>>, Error>;
//     fn decode_primes_from_oth_field(
//         &self,
//         primes: &mut Vec<Zeroizing<Vec<u8>>>,
//     ) -> Result<(), Error>;
// }
//
// impl JsonWebKeyExt for JsonWebKey {
//     /// <https://w3c.github.io/webcrypto/#concept-parse-a-jwk>
//     #[expect(unsafe_code)]
//     fn parse(cx: &mut JSContext, data: &[u8]) -> Result<JsonWebKey, Error> {
//         // Step 1. Let data be the sequence of bytes to be parsed.
//         // (It is given as a method paramter.)
//
//         // Step 2. Let json be the Unicode string that results from interpreting data according to UTF-8.
//         let json = String::from_utf8_lossy(data);
//
//         // Step 3. Convert json to UTF-16.
//         let json: Vec<_> = json.encode_utf16().collect();
//
//         // Step 4. Let result be the object literal that results from executing the JSON.parse
//         // internal function in the context of a new global object, with text argument set to a
//         // JavaScript String containing json.
//         rooted!(&in(cx) let mut result = UndefinedValue());
//         unsafe {
//             if !JS_ParseJSON(cx, json.as_ptr(), json.len() as u32, result.handle_mut()) {
//                 return Err(Error::JSFailed);
//             }
//         }
//
//         // Step 5. Let key be the result of converting result to the IDL dictionary type of JsonWebKey.
//         let key = match JsonWebKey::new(cx, result.handle()) {
//             Ok(ConversionResult::Success(key)) => key,
//             Ok(ConversionResult::Failure(error)) => {
//                 return Err(Error::Type(error.into_owned()));
//             },
//             Err(()) => {
//                 return Err(Error::JSFailed);
//             },
//         };
//
//         // Step 6. If the kty field of key is not defined, then throw a DataError.
//         if key.kty.is_none() {
//             return Err(Error::Data(Some(
//                 "'kty' field of key is not defined".into(),
//             )));
//         }
//
//         // Step 7. Result key.
//         Ok(key)
//     }
//
//     /// Convert a JsonWebKey value to DOMString. We first convert the JsonWebKey value to
//     /// JavaScript value, and then serialize it by performing steps in
//     /// <https://infra.spec.whatwg.org/#serialize-a-javascript-value-to-a-json-string>. This acts
//     /// like the opposite of JsonWebKey::parse if you further convert the stringified result to
//     /// bytes.
//     fn stringify(&self, cx: &mut JSContext) -> Result<Zeroizing<DOMString>, Error> {
//         rooted!(&in(cx) let mut data = UndefinedValue());
//         self.to_jsval(cx, data.handle_mut());
//         serialize_jsval_to_json_utf8(cx, data.handle()).map(Zeroizing::new)
//     }
//
//     fn get_usages_from_key_ops(&self) -> Result<Vec<KeyUsage>, Error> {
//         let mut usages = vec![];
//         for op in self.key_ops.as_ref().ok_or(Error::Data(Some(
//             "'key_ops' member is not present in the JSON Web Key".into(),
//         )))? {
//             usages.push(
//                 KeyUsage::from_str(&op.str())
//                     .map_err(|_| Error::Data(Some("Unknown key usage".into())))?,
//             );
//         }
//         Ok(usages)
//     }
//
//     /// If the key_ops field of jwk is present, and is invalid according to the requirements of
//     /// JSON Web Key [JWK] or does not contain all of the specified usages values, then throw a
//     /// DataError.
//     fn check_key_ops(&self, specified_usages: &[KeyUsage]) -> Result<(), Error> {
//         // If the key_ops field of jwk is present,
//         if let Some(ref key_ops) = self.key_ops {
//             // and is invalid according to the requirements of JSON Web Key [JWK]:
//             // 1. Duplicate key operation values MUST NOT be present in the array.
//             if key_ops
//                 .iter()
//                 .collect::<std::collections::HashSet<_>>()
//                 .len() <
//                 key_ops.len()
//             {
//                 return Err(Error::Data(Some(
//                     "Duplicate key operation values are present in array".into(),
//                 )));
//             }
//             // 2. The "use" and "key_ops" JWK members SHOULD NOT be used together; however, if both
//             //    are used, the information they convey MUST be consistent.
//             if let Some(ref use_) = self.use_ &&
//                 key_ops.iter().any(|op| op != use_)
//             {
//                 return Err(Error::Data(Some(
//                     "Key operations are not consistent with intended use for Json Web Key".into(),
//                 )));
//             }
//
//             // or does not contain all of the specified usages values
//             let key_ops_as_usages = self.get_usages_from_key_ops()?;
//             if !specified_usages
//                 .iter()
//                 .all(|specified_usage| key_ops_as_usages.contains(specified_usage))
//             {
//                 return Err(Error::Data(Some(
//                     "Key operations do not contain all of the specified usage values".into(),
//                 )));
//             }
//         }
//
//         Ok(())
//     }
//
//     // Set the key_ops attribute of jwk to equal the given usages.
//     fn set_key_ops(&mut self, usages: &[KeyUsage]) {
//         self.key_ops = Some(
//             usages
//                 .iter()
//                 .map(|usage| DOMString::from(usage.as_str()))
//                 .collect(),
//         );
//     }
//
//     // Encode a byte sequence to a base64url-encoded string, and set the field to the encoded
//     // string.
//     fn encode_string_field(&mut self, field: JwkStringField, data: &[u8]) {
//         let encoded_data = DOMString::from(Base64UrlUnpadded::encode_string(data));
//         match field {
//             JwkStringField::X => self.x = Some(encoded_data),
//             JwkStringField::Y => self.y = Some(encoded_data),
//             JwkStringField::D => self.d = Some(encoded_data),
//             JwkStringField::N => self.n = Some(encoded_data),
//             JwkStringField::E => self.e = Some(encoded_data),
//             JwkStringField::P => self.p = Some(encoded_data),
//             JwkStringField::Q => self.q = Some(encoded_data),
//             JwkStringField::DP => self.dp = Some(encoded_data),
//             JwkStringField::DQ => self.dq = Some(encoded_data),
//             JwkStringField::QI => self.qi = Some(encoded_data),
//             JwkStringField::K => self.k = Some(encoded_data),
//             JwkStringField::Priv => self.priv_ = Some(encoded_data),
//             JwkStringField::Pub => self.pub_ = Some(encoded_data),
//         }
//     }
//
//     // Decode a field from a base64url-encoded string to a byte sequence. If the field is not a
//     // valid base64url-encoded string, then throw a DataError.
//     fn decode_optional_string_field(
//         &self,
//         field: JwkStringField,
//     ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
//         let field_string = match field {
//             JwkStringField::X => &self.x,
//             JwkStringField::Y => &self.y,
//             JwkStringField::D => &self.d,
//             JwkStringField::N => &self.n,
//             JwkStringField::E => &self.e,
//             JwkStringField::P => &self.p,
//             JwkStringField::Q => &self.q,
//             JwkStringField::DP => &self.dp,
//             JwkStringField::DQ => &self.dq,
//             JwkStringField::QI => &self.qi,
//             JwkStringField::K => &self.k,
//             JwkStringField::Priv => &self.priv_,
//             JwkStringField::Pub => &self.pub_,
//         };
//
//         field_string
//             .as_ref()
//             .map(|field_string| {
//                 Base64UrlUnpadded::decode_vec(&field_string.str()).map(Zeroizing::new)
//             })
//             .transpose()
//             .map_err(|_| Error::Data(Some(format!("Failed to decode {} field in jwk", field))))
//     }
//
//     // Decode a field from a base64url-encoded string to a byte sequence. If the field is not
//     // present or it is not a valid base64url-encoded string, then throw a DataError.
//     fn decode_required_string_field(
//         &self,
//         field: JwkStringField,
//     ) -> Result<Zeroizing<Vec<u8>>, Error> {
//         self.decode_optional_string_field(field)?
//             .ok_or(Error::Data(Some(format!(
//                 "The {} field is not present in jwk",
//                 field
//             ))))
//     }
//
//     // Decode the "r", "d" and "t" field of each entry in the "oth" array, from a base64url-encoded
//     // string to a byte sequence, and append the decoded "r" field to the `primes` list, in the
//     // order of presence in the "oth" array.
//     //
//     // If the "oth" field is present and any of the "p", "q", "dp", "dq" or "qi" field is not
//     // present, then throw a DataError. For each entry in the "oth" array, if any of the "r", "d"
//     // and "t" field is not present or it is not a valid base64url-encoded string, then throw a
//     // DataError.
//     fn decode_primes_from_oth_field(
//         &self,
//         primes: &mut Vec<Zeroizing<Vec<u8>>>,
//     ) -> Result<(), Error> {
//         if self.oth.is_some() &&
//             (self.p.is_none() ||
//                 self.q.is_none() ||
//                 self.dp.is_none() ||
//                 self.dq.is_none() ||
//                 self.qi.is_none())
//         {
//             return Err(Error::Data(Some(
//                 "The oth field is present while at least one of p, q, dp, dq, qi is missing, in jwk".to_string()
//             )));
//         }
//
//         for rsa_other_prime_info in self.oth.as_ref().unwrap_or(&Vec::new()) {
//             let r = Base64UrlUnpadded::decode_vec(
//                 &rsa_other_prime_info
//                     .r
//                     .as_ref()
//                     .ok_or(Error::Data(Some(
//                         "The r field is not present in one of the entry of oth field in jwk"
//                             .to_string(),
//                     )))?
//                     .str(),
//             )
//             .map_err(|_| {
//                 Error::Data(Some(
//                     "Fail to decode r field in one of the entry of oth field in jwk".to_string(),
//                 ))
//             })?;
//             primes.push(Zeroizing::new(r));
//
//             let _d = Base64UrlUnpadded::decode_vec(
//                 &rsa_other_prime_info
//                     .d
//                     .as_ref()
//                     .ok_or(Error::Data(Some(
//                         "The d field is not present in one of the entry of oth field in jwk"
//                             .to_string(),
//                     )))?
//                     .str(),
//             )
//             .map_err(|_| {
//                 Error::Data(Some(
//                     "Fail to decode d field in one of the entry of oth field in jwk".to_string(),
//                 ))
//             })?;
//
//             let _t = Base64UrlUnpadded::decode_vec(
//                 &rsa_other_prime_info
//                     .t
//                     .as_ref()
//                     .ok_or(Error::Data(Some(
//                         "The t field is not present in one of the entry of oth field in jwk"
//                             .to_string(),
//                     )))?
//                     .str(),
//             )
//             .map_err(|_| {
//                 Error::Data(Some(
//                     "Fail to decode t field in one of the entry of oth field in jwk".to_string(),
//                 ))
//             })?;
//         }
//
//         Ok(())
//     }
// }

/// <https://w3c.github.io/webcrypto/#algorithm-normalization-normalize-an-algorithm>
fn normalize_algorithm<Op: Operation>(
    cx: &mut JSContext,
    algorithm: &AlgorithmIdentifier,
) -> Result<Op::RegisteredAlgorithm, Error> {
    match algorithm {
        // If alg is an instance of a DOMString:
        AlgorithmIdentifier::String(name) => {
            // Return the result of running the normalize an algorithm algorithm, with the alg set
            // to a new Algorithm dictionary whose name attribute is alg, and with the op set to
            // op.
            //
            // NOTE: We use the Algorithm dictionary generated by script_bindings since the
            // WebCrypto custom binding struct does not accept unnormalized name in its name member.
            let algorithm = AlgorithmWithDOMString {
                name: name.to_owned(),
            };
            rooted!(&in(cx) let mut algorithm_value = UndefinedValue());
            algorithm.to_jsval(cx, algorithm_value.handle_mut());
            let algorithm_object = RootedTraceableBox::new(Heap::default());
            algorithm_object.set(algorithm_value.to_object());
            normalize_algorithm::<Op>(cx, &AlgorithmIdentifier::Object(algorithm_object))
        },
        // If alg is an object:
        AlgorithmIdentifier::Object(object) => {
            // Step 1. Let registeredAlgorithms be the associative container stored at the op key
            // of supportedAlgorithms.

            // Stpe 2. Let initialAlg be the result of converting the ECMAScript object represented
            // by alg to the IDL dictionary type Algorithm, as defined by [WebIDL].
            // Step 3. If an error occurred, return the error and terminate this algorithm.
            // Step 4. Let algName be the value of the name attribute of initialAlg.
            let algorithm_name = get_required_parameter::<DOMString>(
                cx,
                object.handle(),
                c"name",
                StringificationBehavior::Default,
            )?;

            // Step 5.
            //     If registeredAlgorithms contains a key that is a case-insensitive string match
            //     for algName:
            //         Step 5.1. Set algName to the value of the matching key.
            //         Step 5.2. Let desiredType be the IDL dictionary type stored at algName in
            //         registeredAlgorithms.
            //     Otherwise:
            //         Return a new NotSupportedError and terminate this algorithm.
            // Step 6. Let normalizedAlgorithm be the result of converting the ECMAScript object
            // represented by alg to the IDL dictionary type desiredType, as defined by [WebIDL].
            // Step 7. Set the name attribute of normalizedAlgorithm to algName.
            // Step 8. If an error occurred, return the error and terminate this algorithm.
            // Step 9. Let dictionaries be a list consisting of the IDL dictionary type desiredType
            // and all of desiredType's inherited dictionaries, in order from least to most
            // derived.
            // Step 10. For each dictionary dictionary in dictionaries:
            //     Step 10.1. For each dictionary member member declared on dictionary, in order:
            //         Step 10.1.1. Let key be the identifier of member.
            //         Step 10.1.2. Let idlValue be the value of the dictionary member with key
            //         name of key on normalizedAlgorithm.
            //         Step 10.1.3.
            //             If member is of the type BufferSource and is present:
            //                 Set the dictionary member on normalizedAlgorithm with key name key
            //                 to the result of getting a copy of the bytes held by idlValue,
            //                 replacing the current value.
            //             If member is of the type HashAlgorithmIdentifier:
            //                 Set the dictionary member on normalizedAlgorithm with key name key
            //                 to the result of normalizing an algorithm, with the alg set to
            //                 idlValue and the op set to "digest".
            //             If member is of the type AlgorithmIdentifier:
            //                 Set the dictionary member on normalizedAlgorithm with key name key
            //                 to the result of normalizing an algorithm, with the alg set to
            //                 idlValue and the op set to the operation defined by the
            //                 specification that defines the algorithm identified by algName.
            //
            // NOTE:
            // - The desiredTypes in Step 5.2 are determined by the inner type of
            //   `Op::RegisteredAlgorithm`.
            // - Step 9 and 10 are done by the calling `try_into_with_cx_and_name` within the trait
            //   implementation of `Op::RegisteredAlgorithm::from_object`.
            let algorithm_name = CryptoAlgorithm::from_str_ignore_case(&algorithm_name.str())?;
            let normalized_algorithm =
                Op::RegisteredAlgorithm::from_object(cx, algorithm_name, object.handle())?;

            // Step 11. Return normalizedAlgorithm.
            Ok(normalized_algorithm)
        },
    }
}

// <https://w3c.github.io/webcrypto/#dfn-supportedAlgorithms>
//
// We implement the internal object
// [supportedAlgorithms](https://w3c.github.io/webcrypto/#dfn-supportedAlgorithms) for algorithm
// registration, in the following way.
//
// For each operation v in the list of [supported
// operations](https://w3c.github.io/webcrypto/#supported-operation), we define a struct to
// represent it, which acts a key of the internal object supportedAlgorithms.
//
// We then implement the [`Operation`] trait for these structs. When implementing the trait for
// each of these structs, we set the associated type [`RegisteredAlgorithm`] of [`Operation`] to an
// enum as the value of the operation v in supportedAlgorithms. The enum lists all algorithhms
// supporting the operation v as its variants.
//
// To [define an algorithm](https://w3c.github.io/webcrypto/#concept-define-an-algorithm), each
// variant in the enum has an inner type corresponding to the desired input IDL dictionary type for
// the supported algorithm represented by the variant. Moreover, the enum also need to implement
// the [`NormalizedAlgorithm`] trait since it is used as the output of
// [`normalize_algorithm`].
//
// For example, we define the [`EncryptOperation`] struct to represent the "encrypt" operation, and
// implement the [`Operation`] trait for it. The associated type [`RegisteredAlgorithm`] of
// [`Operation`]  is set to the [`EncryptAlgorithm`] enum, whose variants are cryptographic
// algorithms that support the "encrypt" operation. The variant [`EncryptAlgorithm::AesCtr`] has an
// inner type [`AesCtrParams`] since the desired input IDL dictionary type for "encrypt" operation
// of AES-CTR algorithm is the `AesCtrParams` dictionary. The [`EncryptAlgorithm`] enum also
// implements the [`NormalizedAlgorithm`] trait accordingly.
//
// The algorithm registrations are specified in:
// RSASSA-PKCS1-v1_5: <https://w3c.github.io/webcrypto/#rsassa-pkcs1-registration>
// RSA-PSS:           <https://w3c.github.io/webcrypto/#rsa-pss-registration>
// RSA-OAEP:          <https://w3c.github.io/webcrypto/#rsa-oaep-registration>
// ECDSA:             <https://w3c.github.io/webcrypto/#ecdsa-registration>
// ECDH:              <https://w3c.github.io/webcrypto/#ecdh-registration>
// Ed25519:           <https://w3c.github.io/webcrypto/#ed25519-registration>
// X25519:            <https://w3c.github.io/webcrypto/#x25519-registration>
// Ed448:             <https://wicg.github.io/webcrypto-secure-curves/#ed448-registration>
// X448:              <https://wicg.github.io/webcrypto-secure-curves/#x448-registration>
// AES-CTR:           <https://w3c.github.io/webcrypto/#aes-ctr-registration>
// AES-CBC:           <https://w3c.github.io/webcrypto/#aes-cbc-registration>
// AES-GCM:           <https://w3c.github.io/webcrypto/#aes-gcm-registration>
// AES-KW:            <https://w3c.github.io/webcrypto/#aes-kw-registration>
// HMAC:              <https://w3c.github.io/webcrypto/#hmac-registration>
// SHA:               <https://w3c.github.io/webcrypto/#sha-registration>
// HKDF:              <https://w3c.github.io/webcrypto/#hkdf-registration>
// PBKDF2:            <https://w3c.github.io/webcrypto/#pbkdf2-registration>
// ML-KEM:            <https://wicg.github.io/webcrypto-modern-algos/#ml-kem-registration>
// ML-DSA:            <https://wicg.github.io/webcrypto-modern-algos/#ml-dsa-registration>
// AES-OCB:           <https://wicg.github.io/webcrypto-modern-algos/#aes-ocb-registration>
// ChaCha20-Poly1305: <https://wicg.github.io/webcrypto-modern-algos/#chacha20-poly1305-registration>
// SHA-3:             <https://wicg.github.io/webcrypto-modern-algos/#sha3-registration>
// cSHAKE:            <https://wicg.github.io/webcrypto-modern-algos/#cshake-registration>
// TurboSHAKE:        <https://wicg.github.io/webcrypto-modern-algos/#turboshake-registration>
// KangarooTwelve:    <https://wicg.github.io/webcrypto-modern-algos/#kangarootwelve-registration>
// KMAC:              <https://wicg.github.io/webcrypto-modern-algos/#kmac-registration>
// Argon2:            <https://wicg.github.io/webcrypto-modern-algos/#argon2-registration>

trait Operation {
    type RegisteredAlgorithm: NormalizedAlgorithm;
}

trait NormalizedAlgorithm: Sized {
    /// Step 4 - 10 of <https://w3c.github.io/webcrypto/#algorithm-normalization-normalize-an-algorithm>
    fn from_object(
        cx: &mut JSContext,
        algorithm_name: CryptoAlgorithm,
        object: HandleObject,
    ) -> Fallible<Self>;

    /// Return the name of the normalized algorithm.
    fn name(&self) -> CryptoAlgorithm;

    /// <https://wicg.github.io/webcrypto-modern-algos/#dfn-determine-support-from-operation-steps>
    ///
    /// The default implemenation is to return false, as placeholder. The actual implementation
    /// depends on the operation represented by the trait implementor.
    fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
        // Step 1. If the specified operation or algorithm (or one of its parameter values) is
        // expected to fail (for any key and/or data) for an implementation-specific reason (e.g.
        // known nonconformance to the specification), return false.
        // Step 2. If op is "generateKey" or "importKey", let usages be the empty list.
        // Step 3. For each of the steps of the operation specified by op of the algorithm specified
        // by normalizedAlgorithm:
        //     If the step says to throw an error:
        //         Return false.
        //     If the step says to generate a key:
        //         Return true.
        //     If the step relies on an unavailable parameter, such as key, plaintext or ciphertext:
        //         Return true.
        //     If the step says to return a value:
        //         Return true.
        //     Otherwise:
        //         Execute the step.
        // Step 4. Assert: this step is never reached, because one of the steps of the operation
        // will have said to return a value or throw an error, causing us to return true or false,
        // respectively.
        //
        // NOTE:
        // - Step 3 can be interpreted as executing the specified operation of the specified
        //   algorithm in "dry-run" mode in which it validates the normalizedAlgorithm, length and
        //   usages but does not execute the computation-demanding cryptographic calculation.
        //
        // - Usually, the parameter validations are executed at the beginning of the operation.
        //   Therefore, Step 3 can be done by running the operation with the following changes:
        //   - Replace "throw an DataError/OperationError/NotSupportedError" with "return false".
        //   - When we reach any step that requires unavailable parameters or does the cryptographic
        //     calculation, return true, instead of running the step, and skip the remaining steps
        //     as well.
        //
        // - Since usages is an empty list, it should pass the validation described in the specified
        //   operation of the specified algorithm. So, we simply ignore it here.
        //
        // - The implementer of this trait is expected to be an `enum` listing possible
        //   cryptographic algorithms. In the implementation of this trait, recommend writing a
        //   `match` block on `self` that explicitly lists all patterns so that the Rust compiler
        //   can remind you to add the necessary parameter validation here when a new operation of
        //   an algorithm is added.
        debug_assert!(
            false,
            "determine_support_from_operation_steps() is not implemented \
                for this normalized algorithm."
        );
        false
    }
}

// /// The value of the key "encrypt" in the internal object supportedAlgorithms
// struct EncryptOperation {}
//
// impl Operation for EncryptOperation {
//     type RegisteredAlgorithm = EncryptAlgorithm;
// }
//
// /// Normalized algorithm for the "encrypt" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum EncryptAlgorithm {
//     RsaOaep(RsaOaepParams),
//     AesCtr(AesCtrParams),
//     AesCbc(AesCbcParams),
//     AesGcm(AesGcmParams),
//     AesOcb(AeadParams),
//     ChaCha20Poly1305(AeadParams),
// }
//
// impl NormalizedAlgorithm for EncryptAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsaOaep => Ok(EncryptAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCtr => Ok(EncryptAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(EncryptAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(EncryptAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesOcb => Ok(EncryptAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(EncryptAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"encrypt\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             EncryptAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             EncryptAlgorithm::AesCtr(algorithm) => algorithm.name,
//             EncryptAlgorithm::AesCbc(algorithm) => algorithm.name,
//             EncryptAlgorithm::AesGcm(algorithm) => algorithm.name,
//             EncryptAlgorithm::AesOcb(algorithm) => algorithm.name,
//             EncryptAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             EncryptAlgorithm::RsaOaep(_) => true,
//             EncryptAlgorithm::AesCtr(normalized_algorithm) => {
//                 normalized_algorithm.counter.len() == 16 &&
//                     normalized_algorithm.length != 0 &&
//                     normalized_algorithm.length <= 128
//             },
//             EncryptAlgorithm::AesCbc(normalized_algorithm) => normalized_algorithm.iv.len() == 16,
//             EncryptAlgorithm::AesGcm(normalized_algorithm) => {
//                 normalized_algorithm.iv.len() <= u64::MAX as usize &&
//                     normalized_algorithm
//                         .additional_data
//                         .as_ref()
//                         .is_none_or(|additional_data| additional_data.len() <= u64::MAX as usize) &&
//                     normalized_algorithm.tag_length.is_none_or(|length| {
//                         matches!(length, 32 | 64 | 96 | 104 | 112 | 120 | 128)
//                     })
//             },
//             EncryptAlgorithm::AesOcb(normalized_algorithm) => {
//                 normalized_algorithm.iv.len() <= 15 &&
//                     normalized_algorithm
//                         .tag_length
//                         .is_none_or(|length| matches!(length, 64 | 96 | 128))
//             },
//             EncryptAlgorithm::ChaCha20Poly1305(normalized_algorithm) => {
//                 normalized_algorithm.iv.len() == 12 &&
//                     normalized_algorithm
//                         .tag_length
//                         .is_none_or(|length| length == 128)
//             },
//         }
//     }
// }
//
// impl EncryptAlgorithm {
//     fn encrypt(&self, key: &CryptoKey, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             EncryptAlgorithm::RsaOaep(algorithm) => {
//                 rsa_oaep_operation::encrypt(algorithm, key, plaintext)
//             },
//             EncryptAlgorithm::AesCtr(algorithm) => {
//                 aes_ctr_operation::encrypt(algorithm, key, plaintext)
//             },
//             EncryptAlgorithm::AesCbc(algorithm) => {
//                 aes_cbc_operation::encrypt(algorithm, key, plaintext)
//             },
//             EncryptAlgorithm::AesGcm(algorithm) => {
//                 aes_gcm_operation::encrypt(algorithm, key, plaintext)
//             },
//             EncryptAlgorithm::AesOcb(algorithm) => {
//                 aes_ocb_operation::encrypt(algorithm, key, plaintext)
//             },
//             EncryptAlgorithm::ChaCha20Poly1305(algorithm) => {
//                 chacha20_poly1305_operation::encrypt(algorithm, key, plaintext)
//             },
//         }
//     }
// }
//
// /// The value of the key "decrypt" in the internal object supportedAlgorithms
// struct DecryptOperation {}
//
// impl Operation for DecryptOperation {
//     type RegisteredAlgorithm = DecryptAlgorithm;
// }
//
// /// Normalized algorithm for the "decrypt" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum DecryptAlgorithm {
//     RsaOaep(RsaOaepParams),
//     AesCtr(AesCtrParams),
//     AesCbc(AesCbcParams),
//     AesGcm(AesGcmParams),
//     AesOcb(AeadParams),
//     ChaCha20Poly1305(AeadParams),
// }
//
// impl NormalizedAlgorithm for DecryptAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsaOaep => Ok(DecryptAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCtr => Ok(DecryptAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(DecryptAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(DecryptAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesOcb => Ok(DecryptAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(DecryptAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"decrypt\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             DecryptAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             DecryptAlgorithm::AesCtr(algorithm) => algorithm.name,
//             DecryptAlgorithm::AesCbc(algorithm) => algorithm.name,
//             DecryptAlgorithm::AesGcm(algorithm) => algorithm.name,
//             DecryptAlgorithm::AesOcb(algorithm) => algorithm.name,
//             DecryptAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             DecryptAlgorithm::RsaOaep(_) => true,
//             DecryptAlgorithm::AesCtr(normalized_algorithm) => {
//                 normalized_algorithm.counter.len() == 16 &&
//                     normalized_algorithm.length != 0 &&
//                     normalized_algorithm.length <= 128
//             },
//             DecryptAlgorithm::AesCbc(normalized_algorithm) => normalized_algorithm.iv.len() == 16,
//             DecryptAlgorithm::AesGcm(normalized_algorithm) => {
//                 normalized_algorithm
//                     .tag_length
//                     .as_ref()
//                     .is_none_or(|length| matches!(length, 32 | 64 | 96 | 104 | 112 | 120 | 128)) &&
//                     normalized_algorithm.iv.len() <= u64::MAX as usize &&
//                     normalized_algorithm
//                         .additional_data
//                         .as_ref()
//                         .is_none_or(|additional_data| additional_data.len() <= u64::MAX as usize)
//             },
//             DecryptAlgorithm::AesOcb(normalized_algorithm) => {
//                 normalized_algorithm.iv.len() <= 15 &&
//                     normalized_algorithm
//                         .tag_length
//                         .as_ref()
//                         .is_none_or(|length| matches!(length, 64 | 96 | 128))
//             },
//             DecryptAlgorithm::ChaCha20Poly1305(normalized_algorithm) => {
//                 normalized_algorithm.iv.len() == 12 &&
//                     normalized_algorithm
//                         .tag_length
//                         .as_ref()
//                         .is_none_or(|length| *length == 128)
//             },
//         }
//     }
// }
//
// impl DecryptAlgorithm {
//     fn decrypt(&self, key: &CryptoKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             DecryptAlgorithm::RsaOaep(algorithm) => {
//                 rsa_oaep_operation::decrypt(algorithm, key, ciphertext)
//             },
//             DecryptAlgorithm::AesCtr(algorithm) => {
//                 aes_ctr_operation::decrypt(algorithm, key, ciphertext)
//             },
//             DecryptAlgorithm::AesCbc(algorithm) => {
//                 aes_cbc_operation::decrypt(algorithm, key, ciphertext)
//             },
//             DecryptAlgorithm::AesGcm(algorithm) => {
//                 aes_gcm_operation::decrypt(algorithm, key, ciphertext)
//             },
//             DecryptAlgorithm::AesOcb(algorithm) => {
//                 aes_ocb_operation::decrypt(algorithm, key, ciphertext)
//             },
//             DecryptAlgorithm::ChaCha20Poly1305(algorithm) => {
//                 chacha20_poly1305_operation::decrypt(algorithm, key, ciphertext)
//             },
//         }
//     }
// }
//
// /// The value of the key "sign" in the internal object supportedAlgorithms
// struct SignOperation {}
//
// impl Operation for SignOperation {
//     type RegisteredAlgorithm = SignAlgorithm;
// }
//
// /// Normalized algorithm for the "sign" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum SignAlgorithm {
//     RsassaPkcs1V1_5(Algorithm),
//     RsaPss(RsaPssParams),
//     Ecdsa(EcdsaParams),
//     Ed25519(Algorithm),
//     Ed448(SubtleEd448Params),
//     Hmac(Algorithm),
//     MlDsa(ContextParams),
//     Kmac(KmacParams),
// }
//
// impl NormalizedAlgorithm for SignAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(SignAlgorithm::RsassaPkcs1V1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(SignAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(SignAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(SignAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(SignAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(SignAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 SignAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(SignAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"sign\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             SignAlgorithm::RsassaPkcs1V1_5(algorithm) => algorithm.name,
//             SignAlgorithm::RsaPss(algorithm) => algorithm.name,
//             SignAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             SignAlgorithm::Ed25519(algorithm) => algorithm.name,
//             SignAlgorithm::Ed448(algorithm) => algorithm.name,
//             SignAlgorithm::Hmac(algorithm) => algorithm.name,
//             SignAlgorithm::MlDsa(algorithm) => algorithm.name,
//             SignAlgorithm::Kmac(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             SignAlgorithm::RsassaPkcs1V1_5(_) |
//             SignAlgorithm::RsaPss(_) |
//             SignAlgorithm::Ecdsa(_) |
//             SignAlgorithm::Ed25519(_) => true,
//             SignAlgorithm::Ed448(normalized_algorithm) => normalized_algorithm
//                 .context
//                 .as_ref()
//                 .is_none_or(|context| context.len() <= 255),
//             SignAlgorithm::Hmac(_) => true,
//             SignAlgorithm::MlDsa(normalized_algorithm) => normalized_algorithm
//                 .context
//                 .as_ref()
//                 .is_none_or(|context| context.len() <= 255),
//             SignAlgorithm::Kmac(_) => true,
//         }
//     }
// }
//
// impl SignAlgorithm {
//     fn sign(&self, key: &CryptoKey, message: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             SignAlgorithm::RsassaPkcs1V1_5(_algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::sign(key, message)
//             },
//             SignAlgorithm::RsaPss(algorithm) => rsa_pss_operation::sign(algorithm, key, message),
//             SignAlgorithm::Ecdsa(algorithm) => ecdsa_operation::sign(algorithm, key, message),
//             SignAlgorithm::Ed25519(_algorithm) => ed25519_operation::sign(key, message),
//             SignAlgorithm::Ed448(algorithm) => ed448_operation::sign(algorithm, key, message),
//             SignAlgorithm::Hmac(_algorithm) => hmac_operation::sign(key, message),
//             SignAlgorithm::MlDsa(algorithm) => ml_dsa_operation::sign(algorithm, key, message),
//             SignAlgorithm::Kmac(algorithm) => kmac_operation::sign(algorithm, key, message),
//         }
//     }
// }
//
// /// The value of the key "verify" in the internal object supportedAlgorithms
// struct VerifyOperation {}
//
// impl Operation for VerifyOperation {
//     type RegisteredAlgorithm = VerifyAlgorithm;
// }
//
// /// Normalized algorithm for the "verify" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum VerifyAlgorithm {
//     RsassaPkcs1V1_5(Algorithm),
//     RsaPss(RsaPssParams),
//     Ecdsa(EcdsaParams),
//     Ed25519(Algorithm),
//     Ed448(SubtleEd448Params),
//     Hmac(Algorithm),
//     MlDsa(ContextParams),
//     Kmac(KmacParams),
// }
//
// impl NormalizedAlgorithm for VerifyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(VerifyAlgorithm::RsassaPkcs1V1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(VerifyAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(VerifyAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(VerifyAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(VerifyAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(VerifyAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 VerifyAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(VerifyAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"verify\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             VerifyAlgorithm::RsassaPkcs1V1_5(algorithm) => algorithm.name,
//             VerifyAlgorithm::RsaPss(algorithm) => algorithm.name,
//             VerifyAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             VerifyAlgorithm::Ed25519(algorithm) => algorithm.name,
//             VerifyAlgorithm::Ed448(algorithm) => algorithm.name,
//             VerifyAlgorithm::Hmac(algorithm) => algorithm.name,
//             VerifyAlgorithm::MlDsa(algorithm) => algorithm.name,
//             VerifyAlgorithm::Kmac(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             VerifyAlgorithm::RsassaPkcs1V1_5(_) |
//             VerifyAlgorithm::RsaPss(_) |
//             VerifyAlgorithm::Ecdsa(_) |
//             VerifyAlgorithm::Ed25519(_) => true,
//             VerifyAlgorithm::Ed448(normalized_algorithm) => normalized_algorithm
//                 .context
//                 .as_ref()
//                 .is_none_or(|context| context.len() <= 255),
//             VerifyAlgorithm::Hmac(_) => true,
//             VerifyAlgorithm::MlDsa(normalized_algorithm) => normalized_algorithm
//                 .context
//                 .as_ref()
//                 .is_none_or(|context| context.len() <= 255),
//             VerifyAlgorithm::Kmac(_) => true,
//         }
//     }
// }
//
// impl VerifyAlgorithm {
//     fn verify(&self, key: &CryptoKey, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
//         match self {
//             VerifyAlgorithm::RsassaPkcs1V1_5(_algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::verify(key, message, signature)
//             },
//             VerifyAlgorithm::RsaPss(algorithm) => {
//                 rsa_pss_operation::verify(algorithm, key, message, signature)
//             },
//             VerifyAlgorithm::Ecdsa(algorithm) => {
//                 ecdsa_operation::verify(algorithm, key, message, signature)
//             },
//             VerifyAlgorithm::Ed25519(_algorithm) => {
//                 ed25519_operation::verify(key, message, signature)
//             },
//             VerifyAlgorithm::Ed448(algorithm) => {
//                 ed448_operation::verify(algorithm, key, message, signature)
//             },
//             VerifyAlgorithm::Hmac(_algorithm) => hmac_operation::verify(key, message, signature),
//             VerifyAlgorithm::MlDsa(algorithm) => {
//                 ml_dsa_operation::verify(algorithm, key, message, signature)
//             },
//             VerifyAlgorithm::Kmac(algorithm) => {
//                 kmac_operation::verify(algorithm, key, message, signature)
//             },
//         }
//     }
// }
//
// /// The value of the key "digest" in the internal object supportedAlgorithms
// struct DigestOperation {}
//
// impl Operation for DigestOperation {
//     type RegisteredAlgorithm = DigestAlgorithm;
// }
//
// /// Normalized algorithm for the "digest" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// #[derive(Clone, MallocSizeOf)]
// enum DigestAlgorithm {
//     Sha(Algorithm),
//     Sha3(Algorithm),
//     CShake(CShakeParams),
//     TurboShake(TurboShakeParams),
//     KangarooTwelve(KangarooTwelveParams),
// }
//
// impl NormalizedAlgorithm for DigestAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::Sha1 |
//             CryptoAlgorithm::Sha256 |
//             CryptoAlgorithm::Sha384 |
//             CryptoAlgorithm::Sha512 => Ok(DigestAlgorithm::Sha(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Sha3_256 | CryptoAlgorithm::Sha3_384 | CryptoAlgorithm::Sha3_512 => {
//                 Ok(DigestAlgorithm::Sha3(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::CShake128 | CryptoAlgorithm::CShake256 => Ok(DigestAlgorithm::CShake(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::TurboShake128 | CryptoAlgorithm::TurboShake256 => Ok(
//                 DigestAlgorithm::TurboShake(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::Kt128 | CryptoAlgorithm::Kt256 => Ok(DigestAlgorithm::KangarooTwelve(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"digest\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             DigestAlgorithm::Sha(algorithm) => algorithm.name,
//             DigestAlgorithm::Sha3(algorithm) => algorithm.name,
//             DigestAlgorithm::CShake(algorithm) => algorithm.name,
//             DigestAlgorithm::TurboShake(algorithm) => algorithm.name,
//             DigestAlgorithm::KangarooTwelve(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             DigestAlgorithm::Sha(_) |
//             DigestAlgorithm::Sha3(_) |
//             DigestAlgorithm::CShake(_) |
//             DigestAlgorithm::TurboShake(_) => true,
//             DigestAlgorithm::KangarooTwelve(normalized_algorithm) => {
//                 normalized_algorithm.output_length != 0 &&
//                     normalized_algorithm.output_length.is_multiple_of(8)
//             },
//         }
//     }
// }
//
// impl DigestAlgorithm {
//     fn digest(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             DigestAlgorithm::Sha(algorithm) => sha_operation::digest(algorithm, message),
//             DigestAlgorithm::Sha3(algorithm) => sha3_operation::digest(algorithm, message),
//             DigestAlgorithm::CShake(algorithm) => cshake_operation::digest(algorithm, message),
//             DigestAlgorithm::TurboShake(algorithm) => {
//                 turboshake_operation::digest(algorithm, message)
//             },
//             DigestAlgorithm::KangarooTwelve(algorithm) => {
//                 kangarootwelve_operation::digest(algorithm, message)
//             },
//         }
//     }
// }
//
// impl TryFrom<SerializableDigestAlgorithm> for DigestAlgorithm {
//     type Error = ();
//
//     fn try_from(value: SerializableDigestAlgorithm) -> Result<Self, Self::Error> {
//         match value {
//             SerializableDigestAlgorithm::Sha(algorithm) => {
//                 Ok(DigestAlgorithm::Sha(algorithm.try_into()?))
//             },
//             SerializableDigestAlgorithm::Sha3(algorithm) => {
//                 Ok(DigestAlgorithm::Sha3(algorithm.try_into()?))
//             },
//             SerializableDigestAlgorithm::CShake(algorithm) => {
//                 Ok(DigestAlgorithm::CShake(algorithm.try_into()?))
//             },
//             SerializableDigestAlgorithm::TurboShake(algorithm) => {
//                 Ok(DigestAlgorithm::TurboShake(algorithm.try_into()?))
//             },
//             SerializableDigestAlgorithm::KangarooTwelve(algorithm) => {
//                 Ok(DigestAlgorithm::KangarooTwelve(algorithm.try_into()?))
//             },
//         }
//     }
// }
//
// impl From<&DigestAlgorithm> for SerializableDigestAlgorithm {
//     fn from(value: &DigestAlgorithm) -> Self {
//         match value {
//             DigestAlgorithm::Sha(algorithm) => SerializableDigestAlgorithm::Sha(algorithm.into()),
//             DigestAlgorithm::Sha3(algorithm) => SerializableDigestAlgorithm::Sha3(algorithm.into()),
//             DigestAlgorithm::CShake(algorithm) => {
//                 SerializableDigestAlgorithm::CShake(algorithm.into())
//             },
//             DigestAlgorithm::TurboShake(algorithm) => {
//                 SerializableDigestAlgorithm::TurboShake(algorithm.into())
//             },
//             DigestAlgorithm::KangarooTwelve(algorithm) => {
//                 SerializableDigestAlgorithm::KangarooTwelve(algorithm.into())
//             },
//         }
//     }
// }
//
// /// The value of the key "deriveBits" in the internal object supportedAlgorithms
// struct DeriveBitsOperation {}
//
// impl Operation for DeriveBitsOperation {
//     type RegisteredAlgorithm = DeriveBitsAlgorithm;
// }
//
// /// Normalized algorithm for the "deriveBits" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum DeriveBitsAlgorithm {
//     Ecdh(EcdhKeyDeriveParams),
//     X25519(EcdhKeyDeriveParams),
//     X448(EcdhKeyDeriveParams),
//     Hkdf(HkdfParams),
//     Pbkdf2(Pbkdf2Params),
//     Argon2(Argon2Params),
// }
//
// impl NormalizedAlgorithm for DeriveBitsAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::Ecdh => Ok(DeriveBitsAlgorithm::Ecdh(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X25519 => Ok(DeriveBitsAlgorithm::X25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X448 => Ok(DeriveBitsAlgorithm::X448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hkdf => Ok(DeriveBitsAlgorithm::Hkdf(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Pbkdf2 => Ok(DeriveBitsAlgorithm::Pbkdf2(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Argon2D | CryptoAlgorithm::Argon2I | CryptoAlgorithm::Argon2ID => Ok(
//                 DeriveBitsAlgorithm::Argon2(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"deriveBits\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             DeriveBitsAlgorithm::Ecdh(algorithm) => algorithm.name,
//             DeriveBitsAlgorithm::X25519(algorithm) => algorithm.name,
//             DeriveBitsAlgorithm::X448(algorithm) => algorithm.name,
//             DeriveBitsAlgorithm::Hkdf(algorithm) => algorithm.name,
//             DeriveBitsAlgorithm::Pbkdf2(algorithm) => algorithm.name,
//             DeriveBitsAlgorithm::Argon2(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, length: Option<u32>) -> bool {
//         match self {
//             DeriveBitsAlgorithm::Ecdh(normalized_algorithm) => {
//                 let public_key = normalized_algorithm.public.root();
//                 let Ok(maximum_length) = ecdh_operation::maximum_length(&public_key) else {
//                     return false;
//                 };
//                 public_key.Type() == KeyType::Public &&
//                     public_key.algorithm().name() == normalized_algorithm.name &&
//                     length.is_none_or(|length| length <= maximum_length)
//             },
//             DeriveBitsAlgorithm::X25519(normalized_algorithm) => {
//                 let public_key = normalized_algorithm.public.root();
//                 public_key.Type() == KeyType::Public &&
//                     public_key.algorithm().name() == normalized_algorithm.name &&
//                     length.is_none_or(|length| length <= 256)
//             },
//             DeriveBitsAlgorithm::X448(_) => {
//                 length.is_none_or(|length| x448_operation::SECRET_LENGTH as u32 * 8 >= length)
//             },
//             DeriveBitsAlgorithm::Hkdf(normalized_algorithm) => {
//                 let hash_length = match normalized_algorithm.hash.name() {
//                     CryptoAlgorithm::Sha1 => 160,
//                     CryptoAlgorithm::Sha256 => 256,
//                     CryptoAlgorithm::Sha384 => 384,
//                     CryptoAlgorithm::Sha512 => 512,
//                     _ => return false,
//                 };
//                 length.is_some_and(|length| length % 8 == 0 && length <= 255 * hash_length)
//             },
//             DeriveBitsAlgorithm::Pbkdf2(normalized_algorithm) => {
//                 length.is_some_and(|length| length % 8 == 0) && normalized_algorithm.iterations != 0
//             },
//             DeriveBitsAlgorithm::Argon2(normalized_algorithm) => {
//                 length.is_some_and(|length| length >= 32 && length % 8 == 0) &&
//                     normalized_algorithm
//                         .version
//                         .is_none_or(|version| version == 19) &&
//                     normalized_algorithm.parallelism != 0 &&
//                     normalized_algorithm.parallelism <= 16777215 &&
//                     normalized_algorithm.memory >= 8 * normalized_algorithm.parallelism &&
//                     normalized_algorithm.passes != 0
//             },
//         }
//     }
// }
//
// impl DeriveBitsAlgorithm {
//     fn derive_bits(&self, key: &CryptoKey, length: Option<u32>) -> Result<Vec<u8>, Error> {
//         match self {
//             DeriveBitsAlgorithm::Ecdh(algorithm) => {
//                 ecdh_operation::derive_bits(algorithm, key, length)
//             },
//             DeriveBitsAlgorithm::X25519(algorithm) => {
//                 x25519_operation::derive_bits(algorithm, key, length)
//             },
//             DeriveBitsAlgorithm::X448(algorithm) => {
//                 x448_operation::derive_bits(algorithm, key, length)
//             },
//             DeriveBitsAlgorithm::Hkdf(algorithm) => {
//                 hkdf_operation::derive_bits(algorithm, key, length)
//             },
//             DeriveBitsAlgorithm::Pbkdf2(algorithm) => {
//                 pbkdf2_operation::derive_bits(algorithm, key, length)
//             },
//             DeriveBitsAlgorithm::Argon2(algorithm) => {
//                 argon2_operation::derive_bits(algorithm, key, length)
//             },
//         }
//     }
// }
//
// /// The value of the key "wrapKey" in the internal object supportedAlgorithms
// struct WrapKeyOperation {}
//
// impl Operation for WrapKeyOperation {
//     type RegisteredAlgorithm = WrapKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "wrapKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum WrapKeyAlgorithm {
//     AesKw(Algorithm),
// }
//
// impl NormalizedAlgorithm for WrapKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::AesKw => Ok(WrapKeyAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"wrapKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             WrapKeyAlgorithm::AesKw(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             WrapKeyAlgorithm::AesKw(_) => true,
//         }
//     }
// }
//
// impl WrapKeyAlgorithm {
//     fn wrap_key(&self, key: &CryptoKey, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             WrapKeyAlgorithm::AesKw(_algorithm) => aes_kw_operation::wrap_key(key, plaintext),
//         }
//     }
// }
//
// /// The value of the key "unwrapKey" in the internal object supportedAlgorithms
// struct UnwrapKeyOperation {}
//
// impl Operation for UnwrapKeyOperation {
//     type RegisteredAlgorithm = UnwrapKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "unwrapKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum UnwrapKeyAlgorithm {
//     AesKw(Algorithm),
// }
//
// impl NormalizedAlgorithm for UnwrapKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::AesKw => Ok(UnwrapKeyAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"unwrapKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             UnwrapKeyAlgorithm::AesKw(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             UnwrapKeyAlgorithm::AesKw(_) => true,
//         }
//     }
// }
//
// impl UnwrapKeyAlgorithm {
//     fn unwrap_key(&self, key: &CryptoKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             UnwrapKeyAlgorithm::AesKw(_algorithm) => aes_kw_operation::unwrap_key(key, ciphertext),
//         }
//     }
// }
//
// /// The value of the key "unwrapKey" in the internal object supportedAlgorithms
// struct GenerateKeyOperation {}
//
// impl Operation for GenerateKeyOperation {
//     type RegisteredAlgorithm = GenerateKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "generateKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum GenerateKeyAlgorithm {
//     RsassaPkcs1V1_5(RsaHashedKeyGenParams),
//     RsaPss(RsaHashedKeyGenParams),
//     RsaOaep(RsaHashedKeyGenParams),
//     Ecdsa(EcKeyGenParams),
//     Ecdh(EcKeyGenParams),
//     Ed25519(Algorithm),
//     X25519(Algorithm),
//     Ed448(Algorithm),
//     X448(Algorithm),
//     AesCtr(AesKeyGenParams),
//     AesCbc(AesKeyGenParams),
//     AesGcm(AesKeyGenParams),
//     AesKw(AesKeyGenParams),
//     Hmac(HmacKeyGenParams),
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
//     MlDsa(Algorithm),
//     AesOcb(AesKeyGenParams),
//     ChaCha20Poly1305(Algorithm),
//     Kmac(KmacKeyGenParams),
// }
//
// impl NormalizedAlgorithm for GenerateKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(GenerateKeyAlgorithm::RsassaPkcs1V1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(GenerateKeyAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaOaep => Ok(GenerateKeyAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(GenerateKeyAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdh => Ok(GenerateKeyAlgorithm::Ecdh(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(GenerateKeyAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X25519 => Ok(GenerateKeyAlgorithm::X25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(GenerateKeyAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X448 => Ok(GenerateKeyAlgorithm::X448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCtr => Ok(GenerateKeyAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(GenerateKeyAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(GenerateKeyAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesKw => Ok(GenerateKeyAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(GenerateKeyAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(GenerateKeyAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(GenerateKeyAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 GenerateKeyAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::AesOcb => Ok(GenerateKeyAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(GenerateKeyAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(GenerateKeyAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"generateKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             GenerateKeyAlgorithm::RsassaPkcs1V1_5(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::RsaPss(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Ecdh(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Ed25519(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::X25519(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Ed448(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::X448(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::AesCtr(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::AesCbc(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::AesGcm(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::AesKw(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Hmac(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::MlKem(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::HybridKem(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::MlDsa(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::AesOcb(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//             GenerateKeyAlgorithm::Kmac(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             GenerateKeyAlgorithm::RsassaPkcs1V1_5(normalized_algorithm) |
//             GenerateKeyAlgorithm::RsaPss(normalized_algorithm) |
//             GenerateKeyAlgorithm::RsaOaep(normalized_algorithm) => {
//                 normalized_algorithm.validate_parameters().is_ok()
//             },
//             GenerateKeyAlgorithm::Ecdsa(normalized_algorithm) |
//             GenerateKeyAlgorithm::Ecdh(normalized_algorithm) => {
//                 SUPPORTED_CURVES.contains(&normalized_algorithm.named_curve.as_str())
//             },
//             GenerateKeyAlgorithm::Ed25519(_) |
//             GenerateKeyAlgorithm::X25519(_) |
//             GenerateKeyAlgorithm::Ed448(_) |
//             GenerateKeyAlgorithm::X448(_) => true,
//             GenerateKeyAlgorithm::AesCtr(normalized_algorithm) |
//             GenerateKeyAlgorithm::AesCbc(normalized_algorithm) |
//             GenerateKeyAlgorithm::AesGcm(normalized_algorithm) |
//             GenerateKeyAlgorithm::AesKw(normalized_algorithm) => {
//                 matches!(normalized_algorithm.length, 128 | 192 | 256)
//             },
//             GenerateKeyAlgorithm::Hmac(normalized_algorithm) => {
//                 normalized_algorithm.length.is_none_or(|length| length != 0)
//             },
//             GenerateKeyAlgorithm::MlKem(_) |
//             GenerateKeyAlgorithm::HybridKem(_) |
//             GenerateKeyAlgorithm::MlDsa(_) => true,
//             GenerateKeyAlgorithm::AesOcb(normalized_algorithm) => {
//                 matches!(normalized_algorithm.length, 128 | 192 | 256)
//             },
//             GenerateKeyAlgorithm::ChaCha20Poly1305(_) | GenerateKeyAlgorithm::Kmac(_) => true,
//         }
//     }
// }
//
// impl GenerateKeyAlgorithm {
//     fn generate_key(
//         &self,
//         cx: &mut JSContext,
//         global: &GlobalScope,
//         extractable: bool,
//         usages: Vec<KeyUsage>,
//     ) -> Result<CryptoKeyOrCryptoKeyPair, Error> {
//         match self {
//             GenerateKeyAlgorithm::RsassaPkcs1V1_5(algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::generate_key(
//                     cx,
//                     global,
//                     algorithm,
//                     extractable,
//                     usages,
//                 )
//                 .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::RsaPss(algorithm) => {
//                 rsa_pss_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::RsaOaep(algorithm) => {
//                 rsa_oaep_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::Ecdsa(algorithm) => {
//                 ecdsa_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::Ecdh(algorithm) => {
//                 ecdh_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::Ed25519(_algorithm) => {
//                 ed25519_operation::generate_key(cx, global, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::X25519(_algorithm) => {
//                 x25519_operation::generate_key(cx, global, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::Ed448(_algorithm) => {
//                 ed448_operation::generate_key(cx, global, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::X448(_algorithm) => {
//                 x448_operation::generate_key(cx, global, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::AesCtr(algorithm) => {
//                 aes_ctr_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::AesCbc(algorithm) => {
//                 aes_cbc_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::AesGcm(algorithm) => {
//                 aes_gcm_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::AesKw(algorithm) => {
//                 aes_kw_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::Hmac(algorithm) => {
//                 hmac_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::MlKem(algorithm) => {
//                 ml_kem_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::HybridKem(algorithm) => {
//                 hybrid_kem_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::MlDsa(algorithm) => {
//                 ml_dsa_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKeyPair)
//             },
//             GenerateKeyAlgorithm::AesOcb(algorithm) => {
//                 aes_ocb_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::ChaCha20Poly1305(_algorithm) => {
//                 chacha20_poly1305_operation::generate_key(cx, global, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//             GenerateKeyAlgorithm::Kmac(algorithm) => {
//                 kmac_operation::generate_key(cx, global, algorithm, extractable, usages)
//                     .map(CryptoKeyOrCryptoKeyPair::CryptoKey)
//             },
//         }
//     }
// }
//
// /// The value of the key "importKey" in the internal object supportedAlgorithms
// struct ImportKeyOperation {}
//
// impl Operation for ImportKeyOperation {
//     type RegisteredAlgorithm = ImportKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "importKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum ImportKeyAlgorithm {
//     RsassaPkcs1V1_5(RsaHashedImportParams),
//     RsaPss(RsaHashedImportParams),
//     RsaOaep(RsaHashedImportParams),
//     Ecdsa(EcKeyImportParams),
//     Ecdh(EcKeyImportParams),
//     Ed25519(Algorithm),
//     X25519(Algorithm),
//     Ed448(Algorithm),
//     X448(Algorithm),
//     AesCtr(Algorithm),
//     AesCbc(Algorithm),
//     AesGcm(Algorithm),
//     AesKw(Algorithm),
//     Hmac(HmacImportParams),
//     Hkdf(Algorithm),
//     Pbkdf2(Algorithm),
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
//     MlDsa(Algorithm),
//     AesOcb(Algorithm),
//     ChaCha20Poly1305(Algorithm),
//     Kmac(KmacImportParams),
//     Argon2(Algorithm),
// }
//
// impl NormalizedAlgorithm for ImportKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(ImportKeyAlgorithm::RsassaPkcs1V1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(ImportKeyAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaOaep => Ok(ImportKeyAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(ImportKeyAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdh => Ok(ImportKeyAlgorithm::Ecdh(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(ImportKeyAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X25519 => Ok(ImportKeyAlgorithm::X25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(ImportKeyAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X448 => Ok(ImportKeyAlgorithm::X448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCtr => Ok(ImportKeyAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(ImportKeyAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(ImportKeyAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesKw => Ok(ImportKeyAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(ImportKeyAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hkdf => Ok(ImportKeyAlgorithm::Hkdf(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Pbkdf2 => Ok(ImportKeyAlgorithm::Pbkdf2(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(ImportKeyAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(ImportKeyAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 ImportKeyAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::AesOcb => Ok(ImportKeyAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(ImportKeyAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(ImportKeyAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Argon2D | CryptoAlgorithm::Argon2I | CryptoAlgorithm::Argon2ID => Ok(
//                 ImportKeyAlgorithm::Argon2(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"importKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             ImportKeyAlgorithm::RsassaPkcs1V1_5(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::RsaPss(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Ecdh(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Ed25519(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::X25519(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Ed448(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::X448(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::AesCtr(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::AesCbc(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::AesGcm(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::AesKw(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Hmac(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Hkdf(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Pbkdf2(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::MlKem(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::HybridKem(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::MlDsa(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::AesOcb(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Kmac(algorithm) => algorithm.name,
//             ImportKeyAlgorithm::Argon2(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             ImportKeyAlgorithm::RsassaPkcs1V1_5(_) |
//             ImportKeyAlgorithm::RsaPss(_) |
//             ImportKeyAlgorithm::RsaOaep(_) => true,
//             ImportKeyAlgorithm::Ecdsa(normalized_algorithm) |
//             ImportKeyAlgorithm::Ecdh(normalized_algorithm) => {
//                 SUPPORTED_CURVES.contains(&normalized_algorithm.named_curve.as_str())
//             },
//             ImportKeyAlgorithm::Ed25519(_) |
//             ImportKeyAlgorithm::X25519(_) |
//             ImportKeyAlgorithm::Ed448(_) |
//             ImportKeyAlgorithm::X448(_) |
//             ImportKeyAlgorithm::AesCtr(_) |
//             ImportKeyAlgorithm::AesCbc(_) |
//             ImportKeyAlgorithm::AesGcm(_) |
//             ImportKeyAlgorithm::AesKw(_) => true,
//             ImportKeyAlgorithm::Hmac(normalized_algorithm) => {
//                 normalized_algorithm.length.is_none_or(|length| length != 0)
//             },
//             ImportKeyAlgorithm::Hkdf(_) |
//             ImportKeyAlgorithm::Pbkdf2(_) |
//             ImportKeyAlgorithm::MlKem(_) |
//             ImportKeyAlgorithm::HybridKem(_) |
//             ImportKeyAlgorithm::MlDsa(_) |
//             ImportKeyAlgorithm::AesOcb(_) |
//             ImportKeyAlgorithm::ChaCha20Poly1305(_) |
//             ImportKeyAlgorithm::Kmac(_) |
//             ImportKeyAlgorithm::Argon2(_) => true,
//         }
//     }
// }
//
// impl ImportKeyAlgorithm {
//     fn import_key(
//         &self,
//         cx: &mut JSContext,
//         global: &GlobalScope,
//         format: KeyFormat,
//         key_data: &[u8],
//         extractable: bool,
//         usages: Vec<KeyUsage>,
//     ) -> Result<DomRoot<CryptoKey>, Error> {
//         match self {
//             ImportKeyAlgorithm::RsassaPkcs1V1_5(algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::import_key(
//                     cx,
//                     global,
//                     algorithm,
//                     format,
//                     key_data,
//                     extractable,
//                     usages,
//                 )
//             },
//             ImportKeyAlgorithm::RsaPss(algorithm) => rsa_pss_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::RsaOaep(algorithm) => rsa_oaep_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::Ecdsa(algorithm) => ecdsa_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::Ecdh(algorithm) => ecdh_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::Ed25519(_algorithm) => {
//                 ed25519_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::X25519(_algorithm) => {
//                 x25519_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::Ed448(_algorithm) => {
//                 ed448_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::X448(_algorithm) => {
//                 x448_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::AesCtr(_algorithm) => {
//                 aes_ctr_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::AesCbc(_algorithm) => {
//                 aes_cbc_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::AesGcm(_algorithm) => {
//                 aes_gcm_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::AesKw(_algorithm) => {
//                 aes_kw_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::Hmac(algorithm) => hmac_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::Hkdf(_algorithm) => {
//                 hkdf_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::Pbkdf2(_algorithm) => {
//                 pbkdf2_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::MlKem(algorithm) => ml_kem_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::HybridKem(algorithm) => hybrid_kem_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::MlDsa(algorithm) => ml_dsa_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::AesOcb(_algorithm) => {
//                 aes_ocb_operation::import_key(cx, global, format, key_data, extractable, usages)
//             },
//             ImportKeyAlgorithm::ChaCha20Poly1305(_algorithm) => {
//                 chacha20_poly1305_operation::import_key(
//                     cx,
//                     global,
//                     format,
//                     key_data,
//                     extractable,
//                     usages,
//                 )
//             },
//             ImportKeyAlgorithm::Kmac(algorithm) => kmac_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//             ImportKeyAlgorithm::Argon2(algorithm) => argon2_operation::import_key(
//                 cx,
//                 global,
//                 algorithm,
//                 format,
//                 key_data,
//                 extractable,
//                 usages,
//             ),
//         }
//     }
//
//     /// Return whether the import key operation specified by normalized algorithm would throw an
//     /// error for every value of keyData that is a byte sequence whose length in bits is
//     /// sharedKeyLength when format is "raw-secret".
//     fn will_throw_for_key_data_length(&self, key_data_length: u32) -> bool {
//         match self {
//             ImportKeyAlgorithm::RsassaPkcs1V1_5(_) |
//             ImportKeyAlgorithm::RsaPss(_) |
//             ImportKeyAlgorithm::RsaOaep(_) |
//             ImportKeyAlgorithm::Ecdsa(_) |
//             ImportKeyAlgorithm::Ecdh(_) |
//             ImportKeyAlgorithm::Ed25519(_) |
//             ImportKeyAlgorithm::X25519(_) |
//             ImportKeyAlgorithm::Ed448(_) |
//             ImportKeyAlgorithm::X448(_) => true,
//             ImportKeyAlgorithm::AesCtr(_) |
//             ImportKeyAlgorithm::AesCbc(_) |
//             ImportKeyAlgorithm::AesGcm(_) |
//             ImportKeyAlgorithm::AesKw(_) => !matches!(key_data_length, 128 | 192 | 256),
//             ImportKeyAlgorithm::Hmac(algorithm) => {
//                 key_data_length == 0 ||
//                     algorithm.length.is_some_and(|length| {
//                         length > key_data_length || length + 8 <= key_data_length
//                     })
//             },
//             ImportKeyAlgorithm::Hkdf(_) | ImportKeyAlgorithm::Pbkdf2(_) => false,
//             ImportKeyAlgorithm::MlKem(_) |
//             ImportKeyAlgorithm::HybridKem(_) |
//             ImportKeyAlgorithm::MlDsa(_) => true,
//             ImportKeyAlgorithm::AesOcb(_) => !matches!(key_data_length, 128 | 192 | 256),
//             ImportKeyAlgorithm::ChaCha20Poly1305(_) => key_data_length != 256,
//             ImportKeyAlgorithm::Kmac(algorithm) => algorithm
//                 .length
//                 .is_some_and(|length| length > key_data_length || length + 8 <= key_data_length),
//             ImportKeyAlgorithm::Argon2(_) => false,
//         }
//     }
// }
//
// /// The value of the key "exportKey" in the internal object supportedAlgorithms
// struct ExportKeyOperation {}
//
// impl Operation for ExportKeyOperation {
//     type RegisteredAlgorithm = ExportKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "exportKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum ExportKeyAlgorithm {
//     RsassaPkcs1V1_5(Algorithm),
//     RsaPss(Algorithm),
//     RsaOaep(Algorithm),
//     Ecdsa(Algorithm),
//     Ecdh(Algorithm),
//     Ed25519(Algorithm),
//     X25519(Algorithm),
//     Ed448(Algorithm),
//     X448(Algorithm),
//     AesCtr(Algorithm),
//     AesCbc(Algorithm),
//     AesGcm(Algorithm),
//     AesKw(Algorithm),
//     Hmac(Algorithm),
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
//     MlDsa(Algorithm),
//     AesOcb(Algorithm),
//     ChaCha20Poly1305(Algorithm),
//     Kmac(Algorithm),
// }
//
// impl NormalizedAlgorithm for ExportKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(ExportKeyAlgorithm::RsassaPkcs1V1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(ExportKeyAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaOaep => Ok(ExportKeyAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(ExportKeyAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdh => Ok(ExportKeyAlgorithm::Ecdh(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(ExportKeyAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X25519 => Ok(ExportKeyAlgorithm::X25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(ExportKeyAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X448 => Ok(ExportKeyAlgorithm::X448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCtr => Ok(ExportKeyAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(ExportKeyAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(ExportKeyAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesKw => Ok(ExportKeyAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(ExportKeyAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(ExportKeyAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(ExportKeyAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 ExportKeyAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             CryptoAlgorithm::AesOcb => Ok(ExportKeyAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(ExportKeyAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(ExportKeyAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"exportKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             ExportKeyAlgorithm::RsassaPkcs1V1_5(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::RsaPss(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Ecdh(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Ed25519(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::X25519(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Ed448(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::X448(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::AesCtr(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::AesCbc(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::AesGcm(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::AesKw(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Hmac(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::MlKem(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::HybridKem(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::MlDsa(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::AesOcb(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//             ExportKeyAlgorithm::Kmac(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             ExportKeyAlgorithm::RsassaPkcs1V1_5(_) |
//             ExportKeyAlgorithm::RsaPss(_) |
//             ExportKeyAlgorithm::RsaOaep(_) |
//             ExportKeyAlgorithm::Ecdsa(_) |
//             ExportKeyAlgorithm::Ecdh(_) |
//             ExportKeyAlgorithm::Ed25519(_) |
//             ExportKeyAlgorithm::X25519(_) |
//             ExportKeyAlgorithm::Ed448(_) |
//             ExportKeyAlgorithm::X448(_) |
//             ExportKeyAlgorithm::AesCtr(_) |
//             ExportKeyAlgorithm::AesCbc(_) |
//             ExportKeyAlgorithm::AesGcm(_) |
//             ExportKeyAlgorithm::AesKw(_) |
//             ExportKeyAlgorithm::Hmac(_) |
//             ExportKeyAlgorithm::MlKem(_) |
//             ExportKeyAlgorithm::HybridKem(_) |
//             ExportKeyAlgorithm::MlDsa(_) |
//             ExportKeyAlgorithm::AesOcb(_) |
//             ExportKeyAlgorithm::ChaCha20Poly1305(_) |
//             ExportKeyAlgorithm::Kmac(_) => true,
//         }
//     }
// }
//
// impl ExportKeyAlgorithm {
//     fn export_key(&self, format: KeyFormat, key: &CryptoKey) -> Result<ExportedKey, Error> {
//         match self {
//             ExportKeyAlgorithm::RsassaPkcs1V1_5(_algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::export_key(format, key)
//             },
//             ExportKeyAlgorithm::RsaPss(_algorithm) => rsa_pss_operation::export_key(format, key),
//             ExportKeyAlgorithm::RsaOaep(_algorithm) => rsa_oaep_operation::export_key(format, key),
//             ExportKeyAlgorithm::Ecdsa(_algorithm) => ecdsa_operation::export_key(format, key),
//             ExportKeyAlgorithm::Ecdh(_algorithm) => ecdh_operation::export_key(format, key),
//             ExportKeyAlgorithm::Ed25519(_algorithm) => ed25519_operation::export_key(format, key),
//             ExportKeyAlgorithm::X25519(_algorithm) => x25519_operation::export_key(format, key),
//             ExportKeyAlgorithm::Ed448(_algorithm) => ed448_operation::export_key(format, key),
//             ExportKeyAlgorithm::X448(_algorithm) => x448_operation::export_key(format, key),
//             ExportKeyAlgorithm::AesCtr(_algorithm) => aes_ctr_operation::export_key(format, key),
//             ExportKeyAlgorithm::AesCbc(_algorithm) => aes_cbc_operation::export_key(format, key),
//             ExportKeyAlgorithm::AesGcm(_algorithm) => aes_gcm_operation::export_key(format, key),
//             ExportKeyAlgorithm::AesKw(_algorithm) => aes_kw_operation::export_key(format, key),
//             ExportKeyAlgorithm::Hmac(_algorithm) => hmac_operation::export_key(format, key),
//             ExportKeyAlgorithm::MlKem(_algorithm) => ml_kem_operation::export_key(format, key),
//             ExportKeyAlgorithm::HybridKem(_algorithm) => {
//                 hybrid_kem_operation::export_key(format, key)
//             },
//             ExportKeyAlgorithm::MlDsa(_algorithm) => ml_dsa_operation::export_key(format, key),
//             ExportKeyAlgorithm::AesOcb(_algorithm) => aes_ocb_operation::export_key(format, key),
//             ExportKeyAlgorithm::ChaCha20Poly1305(_algorithm) => {
//                 chacha20_poly1305_operation::export_key(format, key)
//             },
//             ExportKeyAlgorithm::Kmac(_algorithm) => kmac_operation::export_key(format, key),
//         }
//     }
// }
//
// /// The value of the key "get key length" in the internal object supportedAlgorithms
// struct GetKeyLengthOperation {}
//
// impl Operation for GetKeyLengthOperation {
//     type RegisteredAlgorithm = GetKeyLengthAlgorithm;
// }
//
// /// Normalized algorithm for the "get key length" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum GetKeyLengthAlgorithm {
//     AesCtr(AesDerivedKeyParams),
//     AesCbc(AesDerivedKeyParams),
//     AesGcm(AesDerivedKeyParams),
//     AesKw(AesDerivedKeyParams),
//     Hmac(HmacImportParams),
//     Hkdf(Algorithm),
//     Pbkdf2(Algorithm),
//     AesOcb(AesDerivedKeyParams),
//     ChaCha20Poly1305(Algorithm),
//     Kmac(KmacImportParams),
//     Argon2(Algorithm),
// }
//
// impl NormalizedAlgorithm for GetKeyLengthAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::AesCtr => Ok(GetKeyLengthAlgorithm::AesCtr(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesCbc => Ok(GetKeyLengthAlgorithm::AesCbc(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesGcm => Ok(GetKeyLengthAlgorithm::AesGcm(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesKw => Ok(GetKeyLengthAlgorithm::AesKw(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hmac => Ok(GetKeyLengthAlgorithm::Hmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Hkdf => Ok(GetKeyLengthAlgorithm::Hkdf(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Pbkdf2 => Ok(GetKeyLengthAlgorithm::Pbkdf2(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::AesOcb => Ok(GetKeyLengthAlgorithm::AesOcb(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::ChaCha20Poly1305 => Ok(GetKeyLengthAlgorithm::ChaCha20Poly1305(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Kmac128 | CryptoAlgorithm::Kmac256 => Ok(GetKeyLengthAlgorithm::Kmac(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Argon2D | CryptoAlgorithm::Argon2I | CryptoAlgorithm::Argon2ID => {
//                 Ok(GetKeyLengthAlgorithm::Argon2(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"get key length\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             GetKeyLengthAlgorithm::AesCtr(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::AesCbc(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::AesGcm(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::AesKw(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::Hmac(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::Hkdf(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::Pbkdf2(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::AesOcb(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::ChaCha20Poly1305(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::Kmac(algorithm) => algorithm.name,
//             GetKeyLengthAlgorithm::Argon2(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             GetKeyLengthAlgorithm::AesCtr(normalized_derived_key_algorithm) |
//             GetKeyLengthAlgorithm::AesCbc(normalized_derived_key_algorithm) |
//             GetKeyLengthAlgorithm::AesGcm(normalized_derived_key_algorithm) |
//             GetKeyLengthAlgorithm::AesKw(normalized_derived_key_algorithm) => {
//                 matches!(normalized_derived_key_algorithm.length, 128 | 192 | 256)
//             },
//             GetKeyLengthAlgorithm::Hmac(normalized_derived_key_algorithm) => {
//                 normalized_derived_key_algorithm
//                     .length
//                     .is_none_or(|length| length != 0)
//             },
//             GetKeyLengthAlgorithm::Hkdf(_) | GetKeyLengthAlgorithm::Pbkdf2(_) => true,
//             GetKeyLengthAlgorithm::AesOcb(normalized_derived_key_algorithm) => {
//                 matches!(normalized_derived_key_algorithm.length, 128 | 192 | 256)
//             },
//             GetKeyLengthAlgorithm::ChaCha20Poly1305(_) |
//             GetKeyLengthAlgorithm::Kmac(_) |
//             GetKeyLengthAlgorithm::Argon2(_) => true,
//         }
//     }
// }
//
// impl GetKeyLengthAlgorithm {
//     fn get_key_length(&self) -> Result<Option<u32>, Error> {
//         match self {
//             GetKeyLengthAlgorithm::AesCtr(algorithm) => {
//                 aes_ctr_operation::get_key_length(algorithm)
//             },
//             GetKeyLengthAlgorithm::AesCbc(algorithm) => {
//                 aes_cbc_operation::get_key_length(algorithm)
//             },
//             GetKeyLengthAlgorithm::AesGcm(algorithm) => {
//                 aes_gcm_operation::get_key_length(algorithm)
//             },
//             GetKeyLengthAlgorithm::AesKw(algorithm) => aes_kw_operation::get_key_length(algorithm),
//             GetKeyLengthAlgorithm::Hmac(algorithm) => hmac_operation::get_key_length(algorithm),
//             GetKeyLengthAlgorithm::Hkdf(_algorithm) => hkdf_operation::get_key_length(),
//             GetKeyLengthAlgorithm::Pbkdf2(_algorithm) => pbkdf2_operation::get_key_length(),
//             GetKeyLengthAlgorithm::AesOcb(algorithm) => {
//                 aes_ocb_operation::get_key_length(algorithm)
//             },
//             GetKeyLengthAlgorithm::ChaCha20Poly1305(_algorithm) => {
//                 chacha20_poly1305_operation::get_key_length()
//             },
//             GetKeyLengthAlgorithm::Kmac(algorithm) => kmac_operation::get_key_length(algorithm),
//             GetKeyLengthAlgorithm::Argon2(_algorithm) => argon2_operation::get_key_length(),
//         }
//     }
// }
//
// /// The value of the key "encapsulate" in the internal object supportedAlgorithms
// struct EncapsulateOperation {}
//
// impl Operation for EncapsulateOperation {
//     type RegisteredAlgorithm = EncapsulateAlgorithm;
// }
//
// /// Normalized algorithm for the "encapsulate" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum EncapsulateAlgorithm {
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
// }
//
// impl NormalizedAlgorithm for EncapsulateAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(EncapsulateAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(EncapsulateAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"encapsulate\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             EncapsulateAlgorithm::MlKem(algorithm) => algorithm.name,
//             EncapsulateAlgorithm::HybridKem(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             EncapsulateAlgorithm::MlKem(_) | EncapsulateAlgorithm::HybridKem(_) => true,
//         }
//     }
// }
//
// impl EncapsulateAlgorithm {
//     fn encapsulate(&self, key: &CryptoKey) -> Result<EncapsulatedBits, Error> {
//         match self {
//             EncapsulateAlgorithm::MlKem(algorithm) => ml_kem_operation::encapsulate(algorithm, key),
//             EncapsulateAlgorithm::HybridKem(algorithm) => {
//                 hybrid_kem_operation::encapsulate(algorithm, key)
//             },
//         }
//     }
// }
//
// /// The value of the key "decapsulate" in the internal object supportedAlgorithms
// struct DecapsulateOperation {}
//
// impl Operation for DecapsulateOperation {
//     type RegisteredAlgorithm = DecapsulateAlgorithm;
// }
//
// /// Normalized algorithm for the "decapsulate" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum DecapsulateAlgorithm {
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
// }
//
// impl NormalizedAlgorithm for DecapsulateAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(DecapsulateAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(DecapsulateAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"decapsulate\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             DecapsulateAlgorithm::MlKem(algorithm) => algorithm.name,
//             DecapsulateAlgorithm::HybridKem(algorithm) => algorithm.name,
//         }
//     }
//
//     fn determine_support_from_operation_steps(&self, _length: Option<u32>) -> bool {
//         match self {
//             DecapsulateAlgorithm::MlKem(_) | DecapsulateAlgorithm::HybridKem(_) => true,
//         }
//     }
// }
//
// impl DecapsulateAlgorithm {
//     fn decapsulate(&self, key: &CryptoKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
//         match self {
//             DecapsulateAlgorithm::MlKem(algorithm) => {
//                 ml_kem_operation::decapsulate(algorithm, key, ciphertext)
//             },
//             DecapsulateAlgorithm::HybridKem(algorithm) => {
//                 hybrid_kem_operation::decapsulate(algorithm, key, ciphertext)
//             },
//         }
//     }
// }
//
// /// The value of the key "get shared key length" in the internal object supportedAlgorithms
// struct GetSharedKeyLengthOperation {}
//
// impl Operation for GetSharedKeyLengthOperation {
//     type RegisteredAlgorithm = GetSharedKeyLengthAlgorithm;
// }
//
// /// Normalized algorithm for the "get shared key length" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum GetSharedKeyLengthAlgorithm {
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
// }
//
// impl NormalizedAlgorithm for GetSharedKeyLengthAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(GetSharedKeyLengthAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(GetSharedKeyLengthAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"get shared key length\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             GetSharedKeyLengthAlgorithm::MlKem(algorithm) => algorithm.name,
//             GetSharedKeyLengthAlgorithm::HybridKem(algorithm) => algorithm.name,
//         }
//     }
// }
//
// impl GetSharedKeyLengthAlgorithm {
//     fn get_shared_key_length(&self) -> u32 {
//         match self {
//             GetSharedKeyLengthAlgorithm::MlKem(_algorithm) => {
//                 ml_kem_operation::get_shared_key_length()
//             },
//             GetSharedKeyLengthAlgorithm::HybridKem(_algorithm) => {
//                 hybrid_kem_operation::get_shared_key_length()
//             },
//         }
//     }
// }
//
// /// The value of the key "getPublicKey" in the internal object supportedAlgorithms
// struct GetPublicKeyOperation {}
//
// impl Operation for GetPublicKeyOperation {
//     type RegisteredAlgorithm = GetPublicKeyAlgorithm;
// }
//
// /// Normalized algorithm for the "getPublicKey" operation, used as output of
// /// <https://w3c.github.io/webcrypto/#dfn-normalize-an-algorithm>
// enum GetPublicKeyAlgorithm {
//     RsassaPkcs1v1_5(Algorithm),
//     RsaPss(Algorithm),
//     RsaOaep(Algorithm),
//     Ecdsa(Algorithm),
//     Ecdh(Algorithm),
//     Ed25519(Algorithm),
//     X25519(Algorithm),
//     Ed448(Algorithm),
//     X448(Algorithm),
//     MlKem(Algorithm),
//     HybridKem(Algorithm),
//     MlDsa(Algorithm),
// }
//
// impl NormalizedAlgorithm for GetPublicKeyAlgorithm {
//     fn from_object(
//         cx: &mut JSContext,
//         algorithm_name: CryptoAlgorithm,
//         object: HandleObject,
//     ) -> Fallible<Self> {
//         match algorithm_name {
//             CryptoAlgorithm::RsassaPkcs1V1_5 => Ok(GetPublicKeyAlgorithm::RsassaPkcs1v1_5(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaPss => Ok(GetPublicKeyAlgorithm::RsaPss(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::RsaOaep => Ok(GetPublicKeyAlgorithm::RsaOaep(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdsa => Ok(GetPublicKeyAlgorithm::Ecdsa(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ecdh => Ok(GetPublicKeyAlgorithm::Ecdh(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed25519 => Ok(GetPublicKeyAlgorithm::Ed25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X25519 => Ok(GetPublicKeyAlgorithm::X25519(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::Ed448 => Ok(GetPublicKeyAlgorithm::Ed448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::X448 => Ok(GetPublicKeyAlgorithm::X448(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlKem512 | CryptoAlgorithm::MlKem768 | CryptoAlgorithm::MlKem1024 => {
//                 Ok(GetPublicKeyAlgorithm::MlKem(
//                     object.try_into_with_cx_and_name(cx, algorithm_name)?,
//                 ))
//             },
//             CryptoAlgorithm::MlKem768X25519 => Ok(GetPublicKeyAlgorithm::HybridKem(
//                 object.try_into_with_cx_and_name(cx, algorithm_name)?,
//             )),
//             CryptoAlgorithm::MlDsa44 | CryptoAlgorithm::MlDsa65 | CryptoAlgorithm::MlDsa87 => Ok(
//                 GetPublicKeyAlgorithm::MlDsa(object.try_into_with_cx_and_name(cx, algorithm_name)?),
//             ),
//             _ => Err(Error::NotSupported(Some(format!(
//                 "{} does not support \"getPublicKey\" operation",
//                 algorithm_name.as_str()
//             )))),
//         }
//     }
//
//     fn name(&self) -> CryptoAlgorithm {
//         match self {
//             GetPublicKeyAlgorithm::RsassaPkcs1v1_5(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::RsaPss(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::RsaOaep(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::Ecdsa(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::Ecdh(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::Ed25519(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::X25519(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::Ed448(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::X448(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::MlKem(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::HybridKem(algorithm) => algorithm.name,
//             GetPublicKeyAlgorithm::MlDsa(algorithm) => algorithm.name,
//         }
//     }
// }
//
// impl GetPublicKeyAlgorithm {
//     fn get_public_key(
//         &self,
//         cx: &mut JSContext,
//         global: &GlobalScope,
//         key: &CryptoKey,
//         algorithm: &KeyAlgorithmAndDerivatives,
//         usages: Vec<KeyUsage>,
//     ) -> Result<DomRoot<CryptoKey>, Error> {
//         match self {
//             GetPublicKeyAlgorithm::RsassaPkcs1v1_5(_algorithm) => {
//                 rsassa_pkcs1_v1_5_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::RsaPss(_algorithm) => {
//                 rsa_pss_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::RsaOaep(_algorithm) => {
//                 rsa_oaep_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::Ecdsa(_algorithm) => {
//                 ecdsa_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::Ecdh(_algorithm) => {
//                 ecdh_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::Ed25519(_algorithm) => {
//                 ed25519_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::X25519(_algorithm) => {
//                 x25519_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::Ed448(_algorithm) => {
//                 ed448_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::X448(_algorithm) => {
//                 x448_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::MlKem(_algorithm) => {
//                 ml_kem_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::HybridKem(_algorithm) => {
//                 hybrid_kem_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//             GetPublicKeyAlgorithm::MlDsa(_algorithm) => {
//                 ml_dsa_operation::get_public_key(cx, global, key, algorithm, usages)
//             },
//         }
//     }
// }
