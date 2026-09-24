/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::{Reflector, reflect_dom_object};

use crate::dom::bindings::error::{Error, Fallible};
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::codegen::Bindings::WebTransportSendGroupBinding::{
    WebTransportSendGroupMethods,
};
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::globalscope::GlobalScope;
use crate::dom::webtransport::webtransport::WebTransport;

#[dom_struct]
pub(crate) struct WebTransportSendGroup {
    reflector_: Reflector,

    /// <https://w3c.github.io/webtransport/#dom-webtransportsendgroup-transport-slot>
    transport: Dom<WebTransport>,
}

impl WebTransportSendGroup {
    fn new_inherited(transport: &WebTransport) -> WebTransportSendGroup {
        WebTransportSendGroup {
            reflector_: Reflector::new(),
            transport: Dom::from_ref(transport),
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        transport: &WebTransport,
    ) -> DomRoot<WebTransportSendGroup> {
        reflect_dom_object(cx, Box::new(WebTransportSendGroup::new_inherited(transport)), global)
    }

    pub(crate) fn transport(&self) -> &WebTransport {
        &self.transport
    }

    /// <https://w3c.github.io/webtransport/#webtransportsendgroup-create>
    pub(crate) fn create(
        cx: &mut JSContext,
        global: &GlobalScope,
        transport: &WebTransport
    ) -> DomRoot<WebTransportSendGroup> {
        // Step 1. Let sendGroup be a new WebTransportSendGroup, with:
        //     [[Transport]]
        //         transport
        // Step 2. Return sendGroup.
        WebTransportSendGroup::new(cx, global, transport)
    }
}
