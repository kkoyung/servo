/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

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
