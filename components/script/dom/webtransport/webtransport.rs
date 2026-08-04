/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::context::JSContext;
use js::rust::HandleObject;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_proto};

use crate::dom::bindings::codegen::Bindings::WebTransportBinding::{
    WebTransportMethods, WebTransportOptions,
};
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::USVString;
use crate::dom::bindings::trace::RootedTraceableBox;
use crate::dom::globalscope::GlobalScope;

#[dom_struct]
pub(crate) struct WebTransport {
    reflector_: Reflector,
}

impl WebTransport {
    fn new_inherited() -> WebTransport {
        WebTransport {
            reflector_: Reflector::new(),
        }
    }

    pub(crate) fn new_with_proto(
        cx: &mut JSContext,
        global: &GlobalScope,
        proto: Option<HandleObject>,
    ) -> DomRoot<WebTransport> {
        reflect_dom_object_with_proto(cx, Box::new(WebTransport::new_inherited()), global, proto)
    }
}

impl WebTransportMethods<crate::DomTypeHolder> for WebTransport {
    fn Constructor(
        cx: &mut JSContext,
        global: &GlobalScope,
        proto: Option<HandleObject>,
        _url: USVString,
        _options: RootedTraceableBox<WebTransportOptions>,
    ) -> DomRoot<WebTransport> {
        WebTransport::new_with_proto(cx, global, proto)
    }
}
