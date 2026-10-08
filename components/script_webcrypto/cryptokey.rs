/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::marker::PhantomData;
// use std::str::FromStr;

use dom_struct::dom_struct;
use itertools::Itertools;
// use js::rooted;
use js::context::NoGC;
use js::conversions::ToJSValConvertible;
use js::jsapi::{Heap, JSObject, Value};
use js::rust::MutableHandleObject;
use jstraceable_derive::JSTraceable;
// use malloc_size_of::MallocSizeOf;
use malloc_size_of_derive::MallocSizeOf;
use rustc_hash::FxHashMap;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_wrap};
use script_bindings::serializable::Serializable;
use script_bindings::structuredclone::StructuredData;
use script_bindings::DomTypes;
use servo_base::id::{CryptoKeyId, CryptoKeyIndex};
use servo_constellation_traits::{SerializableCryptoKey, SerializableCryptoKeyHandle};
// use strum::VariantArray;
// use zeroize::Zeroizing;
use script_bindings::codegen::GenericBindings::CryptoKeyBinding::{
    CryptoKeyMethods, CryptoKeyPair, KeyType, KeyUsage, Wrap as CryptoKeyWrap,
};
use script_bindings::error::{Error, ErrorResult};
use script_bindings::root::DomRoot;

use crate::traits::Equivalence;

/// <https://w3c.github.io/webcrypto/#cryptokey-interface>
#[dom_struct]
pub struct CryptoKey<D: DomTypes> {
    reflector_: Reflector,

    /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-type>
    key_type: KeyType,

    /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-extractable>
    extractable: bool,

    // /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-algorithm>
    // ///
    // /// The contents of the [[algorithm]] internal slot shall be, or be derived from, a
    // /// KeyAlgorithm.
    // #[no_trace]
    // algorithm: KeyAlgorithmAndDerivatives,

    /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-algorithm_cached>
    #[ignore_malloc_size_of = "Defined in mozjs"]
    algorithm_cached: Heap<*mut JSObject>,

    /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-usages>
    ///
    /// The contents of the [[usages]] internal slot shall be of type Sequence<KeyUsage>.
    usages: Vec<KeyUsage>,

    /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-usages_cached>
    #[ignore_malloc_size_of = "Defined in mozjs"]
    usages_cached: Heap<*mut JSObject>,

    // /// <https://w3c.github.io/webcrypto/#dfn-CryptoKey-slot-handle>
    // #[no_trace]
    // handle: Handle,

    #[no_trace = "PhantomData does not exist"]
    phantom: PhantomData<D>,
}

impl<D> CryptoKey<D>
where
    D: Equivalence,
{
    fn new_inherited(
        key_type: KeyType,
        extractable: bool,
        // algorithm: KeyAlgorithmAndDerivatives,
        usages: Vec<KeyUsage>,
        // handle: Handle,
    ) -> CryptoKey<D> {
        CryptoKey {
            reflector_: Reflector::new(),
            key_type,
            extractable,
            // algorithm,
            algorithm_cached: Heap::default(),
            usages,
            usages_cached: Heap::default(),
            // handle,
            phantom: PhantomData,
        }
    }

    pub fn new(
        cx: &mut js::context::JSContext,
        global: &D::GlobalScope,
        key_type: KeyType,
        extractable: bool,
        // algorithm: KeyAlgorithmAndDerivatives,
        usages: Vec<KeyUsage>,
        // handle: Handle,
    ) -> DomRoot<CryptoKey<D>> {
        let crypto_key = reflect_dom_object_with_wrap::<D, _, _>(
            cx,
            Box::new(CryptoKey::new_inherited(
                key_type,
                extractable,
                // algorithm.clone(),
                usages.clone(),
                // handle,
            )),
            global,
            CryptoKeyWrap::<D>,
        );

        // // Create and store a cached object of algorithm
        // rooted!(&in(cx) let mut algorithm_object_value: Value);
        // algorithm.to_jsval(cx, algorithm_object_value.handle_mut());
        // crypto_key
        //     .algorithm_cached
        //     .set(algorithm_object_value.to_object());
        //
        // // Create and store a cached object of usages
        // rooted!(&in(cx) let mut usages_object_value: Value);
        // usages.to_jsval(cx, usages_object_value.handle_mut());
        // crypto_key
        //     .usages_cached
        //     .set(usages_object_value.to_object());

        crypto_key
    }

    // pub(crate) fn algorithm(&self) -> &KeyAlgorithmAndDerivatives {
    //     &self.algorithm
    // }

    pub(crate) fn usages(&self) -> &[KeyUsage] {
        &self.usages
    }

    // pub(crate) fn handle(&self) -> &Handle {
    //     &self.handle
    // }

    /// Ensure that the [[type]] internal slot of key is same as `expected`. If the [[type]]
    /// internal slot of key is not same as `expected`, then throw an InvalidAccessError.
    pub(crate) fn ensure_type(&self, expected: KeyType) -> ErrorResult {
        if self.key_type == expected {
            Ok(())
        } else {
            Err(Error::InvalidAccess(Some(match expected {
                KeyType::Public => "The key is not a public key".into(),
                KeyType::Private => "The key is not a private key".into(),
                KeyType::Secret => "The key is not a secret key".into(),
            })))
        }
    }
}

impl<D> CryptoKeyMethods<D> for CryptoKey<D>
where
    D: DomTypes,
{
    /// <https://w3c.github.io/webcrypto/#dom-cryptokey-type>
    fn Type(&self) -> KeyType {
        // Reflects the [[type]] internal slot, which contains the type of the underlying key.
        self.key_type
    }

    /// <https://w3c.github.io/webcrypto/#dom-cryptokey-extractable>
    fn Extractable(&self) -> bool {
        // Reflects the [[extractable]] internal slot, which indicates whether or not the raw
        // keying material may be exported by the application.
        self.extractable
    }

    /// <https://w3c.github.io/webcrypto/#dom-cryptokey-algorithm>
    fn Algorithm(&self, mut return_value: MutableHandleObject) {
        // Returns the cached ECMAScript object associated with the [[algorithm]] internal slot.
        return_value.set(self.algorithm_cached.get())
    }

    /// <https://w3c.github.io/webcrypto/#dom-cryptokey-usages>
    fn Usages(&self, mut return_value: MutableHandleObject) {
        // Returns the cached ECMAScript object associated with the [[usages]] internal slot, which
        // indicates which cryptographic operations are permissible to be used with this key.
        return_value.set(self.usages_cached.get())
    }
}

impl<D> Serializable<D> for CryptoKey<D>
where
    D: Equivalence,
{
    type Index = CryptoKeyIndex;
    type Data = SerializableCryptoKey;

    /// <https://w3c.github.io/webcrypto/#cryptokey-interface-serializable>
    fn serialize(&self, _no_gc: &NoGC) -> Result<(CryptoKeyId, Self::Data), ()> {
        // // Step 1. Set serialized.[[Type]] to the [[type]] internal slot of value.
        // // Step 2. Set serialized.[[Extractable]] to the [[extractable]] internal slot of value.
        // // Step 3. Set serialized.[[Algorithm]] to the sub-serialization of the [[algorithm]]
        // // internal slot of value.
        // // Step 4. Set serialized.[[Usages]] to the sub-serialization of the [[usages]] internal
        // // slot of value.
        // // Step 5. Set serialized.[[Handle]] to the [[handle]] internal slot of value.
        // let serialized = SerializableCryptoKey {
        //     key_type: self.key_type.as_str().into(),
        //     extractable: self.extractable,
        //     algorithm: (&self.algorithm).into(),
        //     usages: self
        //         .usages
        //         .iter()
        //         .map(|usage| usage.as_str().into())
        //         .collect(),
        //     handle: (&self.handle).try_into()?,
        // };
        // Ok((CryptoKeyId::new(), serialized))
        todo!()
    }

    /// <https://w3c.github.io/webcrypto/#cryptokey-interface-serializable>
    fn deserialize(
        cx: &mut js::context::JSContext,
        owner: &D::GlobalScope,
        serialized: Self::Data,
    ) -> Result<DomRoot<Self>, ()> {
        // // Step 1. Initialize the [[type]] internal slot of value to serialized.[[Type]].
        // // Step 2. Initialize the [[extractable]] internal slot of value to
        // // serialized.[[Extractable]].
        // // Step 3. Initialize the [[algorithm]] internal slot of value to the sub-deserialization of
        // // serialized.[[Algorithm]].
        // // Step 4. Initialize the [[usages]] internal slot of value to the sub-deserialization of
        // // serialized.[[Usages]].
        // // Step 5. Initialize the [[handle]] internal slot of value to serialized.[[Handle]].
        // Ok(CryptoKey::new(
        //     cx,
        //     owner,
        //     KeyType::from_str(&serialized.key_type)?,
        //     serialized.extractable,
        //     serialized.algorithm.try_into()?,
        //     serialized
        //         .usages
        //         .iter()
        //         .map(|usage| KeyUsage::from_str(usage))
        //         .collect::<Result<Vec<_>, _>>()?,
        //     serialized.handle.try_into()?,
        // ))
        todo!()
    }

    fn serialized_storage<'a>(
        reader: StructuredData<'a, '_>,
    ) -> &'a mut Option<FxHashMap<CryptoKeyId, Self::Data>> {
        // match reader {
        //     StructuredData::Reader(reader) => &mut reader.crypto_keys,
        //     StructuredData::Writer(writer) => &mut writer.crypto_keys,
        // }
        todo!()
    }
}
