/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// use std::cell::Ref;
// use std::rc::Rc;
// use std::sync::Arc;
//
// use euclid::default::Size2D;
// use js::context::JSContext;
// use pixels::Snapshot;
use script_bindings::DomTypes;
// use script_bindings::callback::{CallbackContainer, HasCallbackHolder, RootedCallback};
// use script_bindings::error::{Error, Fallible};
// use script_bindings::reflector::{DomGlobalGeneric, DomObject};
// use script_bindings::tasks::TaskOnce;
// use serde_core::Serialize;
// use servo_base::generic_channel::GenericCallback;
// use servo_url::MutableOrigin;

use crate::cryptokey::CryptoKey;
use crate::subtlecrypto::SubtleCrypto;

// This trait enforces the equivalence of all local types with the types in DomTypes.
trait_set::trait_set! {
    pub trait Equivalence = DomTypes<
        CryptoKey = CryptoKey<Self>,
        SubtleCrypto = SubtleCrypto<Self>>;
        // // General Bounds
        // GlobalScope: WebCryptoGlobalTrait<Self>>;

    // pub trait WebCryptoPromise<D: DomTypes>;
    // pub trait WebCryptoPromise<D: DomTypes> =
    //     WebCryptoPromiseCallbackTrait<D, SubtleCrypto<D>, ()>;
}
