/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use script_bindings::reflector::{DomGlobalGeneric, DomObject};
use script_webcrypto::traits::WebCryptoGlobalTrait;
use script_webcrypto::traits::WebCryptoPromiseCallbackTrait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use servo_base::generic_channel::GenericCallback;

use crate::dom::GlobalScope;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::promise::RootedPromise;
use crate::routed_promise::{RoutedPromiseListener, callback_promise};
use crate::tasks::task::TaskOnce;

pub(crate) mod crypto;
pub(crate) mod cryptokey {
    pub(crate) type CryptoKey = script_webcrypto::cryptokey::CryptoKey<crate::DomTypeHolder>;
}
pub(crate) mod subtlecrypto {
    pub(crate) type SubtleCrypto = script_webcrypto::subtlecrypto::SubtleCrypto<crate::DomTypeHolder>;
}

// impl<S, T> WebCryptoPromiseCallbackTrait<crate::DomTypeHolder, S, T> for RootedPromise
// where
//     S: DomObject
//         + DomGlobalGeneric<crate::DomTypeHolder>
//         + RoutedPromiseListener<crate::DomTypeHolder, T>,
//     T: Serialize + 'static + Send + DeserializeOwned,
// {
//     fn callback_promise_dom_manipulation_task_source(&self, d: &S) -> GenericCallback<T> {
//         let task_manager = <S as DomGlobal>::global(d).task_manager();
//         callback_promise(self, d, task_manager.dom_manipulation_task_source())
//     }
// }

impl WebCryptoGlobalTrait<crate::DomTypeHolder> for GlobalScope {
    fn queue_crypto_task_source(&self, task: impl TaskOnce + 'static) {
        self.task_manager().webgpu_task_source().queue(task);
    }

    fn queue_dom_manipulation_task_source(&self, task: impl TaskOnce + 'static) {
        self.task_manager().dom_manipulation_task_source().queue(task);
    }
}

// impl SubtleCryptoTrait<crate::DomTypeHolder> for SubtleCrypto {
//     fn new(cx: &mut JSContext, global: &GlobalScope) -> Self {
//
//     }
// }
