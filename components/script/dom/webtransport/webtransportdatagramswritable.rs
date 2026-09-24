/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::time::SystemTime;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::rust::{HandleValue, HandleObject};
use script_bindings::reflector::{Reflector, reflect_dom_object_with_proto};
use servo_url::ServoUrl;
use js::conversions::FromJSValConvertible;

use crate::dom::bindings::error::{Error, ErrorResult, Fallible};
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::codegen::Bindings::WebTransportDatagramsWritableBinding::{
    WebTransportDatagramsWritableMethods,
};
use crate::dom::bindings::root::{Dom, DomRoot, MutNullableDom};
use crate::dom::bindings::str::USVString;
use crate::dom::bindings::trace::RootedTraceableBox;
use crate::dom::globalscope::GlobalScope;
use crate::dom::stream::writablestream::WritableStream;
use crate::dom::stream::writablestreamdefaultcontroller::{WritableStreamDefaultController, UnderlyingSinkType};
use crate::dom::promise::{Promise, RootedPromise, TracedPromise};
use crate::dom::stream::countqueuingstrategy::{extract_high_water_mark, extract_size_algorithm};
use crate::dom::bindings::codegen::Bindings::QueuingStrategyBinding::QueuingStrategy;
use crate::dom::webtransport::webtransport::WebTransport;
use crate::dom::bindings::buffer_source::get_buffer_source_copy;
use crate::dom::bindings::codegen::UnionTypes::ArrayBufferViewOrArrayBuffer;
use crate::dom::webtransport::webtransportsendgroup::WebTransportSendGroup;

#[dom_struct]
pub(crate) struct WebTransportDatagramsWritable {
    writable_stream: WritableStream,

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-outgoingdatagramsqueue-slot>
    outgoing_datagrams_queue: RefCell<VecDeque<(Vec<u8>, SystemTime, TracedPromise)>>,

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-transport-slot>
    transport: Dom<WebTransport>,

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendgroup-slot>
    send_group: MutNullableDom<WebTransportSendGroup>,

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendorder-slot>
    send_order: Cell<i64>,
}

impl WebTransportDatagramsWritable {
    fn new_inherited(
        transport: &WebTransport,
    ) -> WebTransportDatagramsWritable {
        WebTransportDatagramsWritable {
            writable_stream: WritableStream::new_inherited(),
            outgoing_datagrams_queue: Default::default(),
            transport: Dom::from_ref(transport),
            send_group: MutNullableDom::new(None),
            send_order: Cell::new(0),
        }
    }

    fn new_with_proto(
        cx: &mut JSContext,
        global: &GlobalScope,
        proto: Option<HandleObject>,
        transport: &WebTransport,
    ) -> DomRoot<WebTransportDatagramsWritable> {
        reflect_dom_object_with_proto(cx, Box::new(WebTransportDatagramsWritable::new_inherited(transport)), global, proto)
    }

    /// <https://w3c.github.io/webtransport/#webtransportdatagramswritable-create>
    fn create(
        cx: &mut JSContext,
        global: &GlobalScope,
        transport: &WebTransport,
    ) -> Fallible<DomRoot<WebTransportDatagramsWritable>> {
        // Step 1. Let stream be a new WebTransportDatagramsWritable, with:
        //     [[OutgoingDatagramsQueue]]
        //         an empty queue
        //     [[Transport]]
        //         transport
        //     [[SendGroup]]
        //         sendGroup
        //     [[SendOrder]]
        //         sendOrder
        let stream = WebTransportDatagramsWritable::new_with_proto(cx, global, None, transport);

        // Step 2. Let writeDatagramsAlgorithm be an action that runs writeDatagrams with transport
        // and stream.
        // Step 3. Set up stream with writeAlgorithm set to writeDatagramsAlgorithm.
        let size_algorithm = extract_size_algorithm(cx, &QueuingStrategy::default());
        let controller = WritableStreamDefaultController::new(
            cx,
            global,
            UnderlyingSinkType::WebTransportDatagramsWritable(
                Dom::from_ref(&stream),
                Dom::from_ref(transport)
            ),
            1.0,
            size_algorithm,
        );
        controller.setup(cx, global, &stream.writable_stream)?;

        // Step 4. Return stream.
        Ok(stream)
    }

    // /// Step 3 of <https://w3c.github.io/webtransport/#webtransportdatagramswritable-create>
    // fn setup(
    //     cx: &mut JSContext,
    //     global: &GlobalScope,
    // ) {
    //     // <https://streams.spec.whatwg.org/#writablestream-set-up>
    //
    //     // Step 1. Let startAlgorithm be an algorithm that returns undefined.
    //     let start_algorithm = None;
    //
    //     // Step 2. Let closeAlgorithmWrapper be an algorithm that runs these steps:
    //     // Step 2.1. Let result be the result of running closeAlgorithm, if closeAlgorithm was
    //     // given, or null otherwise. If this throws an exception e, return a promise rejected with
    //     // e.
    //     // Step 2.2. If result is a Promise, then return result.
    //     // Step 2.3. Return a promise resolved with undefined.
    //     let close_algorithm = None;
    //
    //     // Step 3. Let abortAlgorithmWrapper be an algorithm that runs these steps given reason:
    //     // Step 3.1. Let result be the result of running abortAlgorithm given reason, if
    //     // abortAlgorithm was given, or null otherwise. If this throws an exception e, return a
    //     // promise rejected with e.
    //     // Step 3.2. If result is a Promise, then return result.
    //     // Step 3.3. Return a promise resolved with undefined.
    //     let abort_algorithm = None;
    //
    //     // Step 4. If sizeAlgorithm was not given, then set it to an algorithm that returns 1.
    //     let size_algorithm = extract_size_algorithm(cx, &QueuingStrategy::default());
    //
    //     // Step 5. Perform ! InitializeWritableStream(stream).
    //     let stream = WritableStream::new_with_proto(cx, global, None);
    //
    //     // TODO:
    //     // Step 6. Let controller be a new WritableStreamDefaultController.
    //     let controller = WritableStreamDefaultController::new(
    //         cx,
    //         global,
    //         UnderlyingSinkType::WebTransportDatagramsWritable(),
    //         1.0,
    //         extract_size_algorithm(cx, &QueuingStrategy::default()),
    //     );
    //
    //     // Step 7. Perform ! SetUpWritableStreamDefaultController(stream, controller,
    //     // startAlgorithm, writeAlgorithm, closeAlgorithmWrapper, abortAlgorithmWrapper,
    //     // highWaterMark, sizeAlgorithm).
    //     controller.setup(cx, global, &stream)?;
    //
    // }

    /// <https://w3c.github.io/webtransport/#writedatagrams>
    pub(crate) fn write_datagrams(
        &self,
        cx: &mut JSContext,
        global: &GlobalScope,
        transport: &WebTransport,
        data: HandleValue,
    ) -> RootedPromise {
        // Step 1. Let timestamp be a timestamp representing now.
        let timestamp = SystemTime::now();

        // Step 2. If data is not a BufferSource object, then return a promise rejected with a
        // TypeError.
        let Ok(conversion_result) = ArrayBufferViewOrArrayBuffer::from_jsval(cx, data, ()) else {
            let promise = Promise::new_rooted(cx, global);
            promise.reject_error(cx, Error::Type(c"The data is not a BufferSource".into()));
            return promise;
        };
        let Some(data) = conversion_result.get_success_value() else {
            let promise = Promise::new_rooted(cx, global);
            promise.reject_error(cx, Error::Type(c"The data is not a BufferSource".into()));
            return promise;
        };

        // TODO:
        // Step 3. Let datagrams be transport.[[Datagrams]].
        // Step 4. If datagrams.[[OutgoingMaxDatagramSize]] is less than data’s [[ByteLength]],
        // return a promise resolved with undefined.

        // Step 5. Let promise be a new promise.
        let promise = Promise::new_rooted(cx, &global);

        // Step 6. Let bytes be a copy of bytes which data represents.
        let bytes = get_buffer_source_copy(data.into());

        // Step 7. Let chunk be (bytes, timestamp, promise).
        // Step 8. Enqueue chunk to writable.[[OutgoingDatagramsQueue]].
        self.outgoing_datagrams_queue.borrow_mut().push_back((bytes, timestamp, promise.to_traced()));

        // TODO:
        // Step 9. If the length of writable.[[OutgoingDatagramsQueue]] is less than
        // datagrams.[[OutgoingMaxBufferedDatagrams]], then resolve promise with undefined.

        // Step 10. Return promise.
        promise
    }
}

impl WebTransportDatagramsWritableMethods<crate::DomTypeHolder> for WebTransportDatagramsWritable {
    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendgroup>
    fn GetSendGroup(&self) -> Fallible<Option<DomRoot<WebTransportSendGroup>>> {
        // Step 1. Return this’s [[SendGroup]].
        Ok(self.send_group.get())
    }

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendgroup>
    fn SetSendGroup(&self, value: Option<&WebTransportSendGroup>) -> ErrorResult {
        // Step 1. If value is non-null, and value.[[Transport]] is not this.[[Transport]], throw an
        // InvalidStateError.
        if value.is_some_and(|value| *value.transport() != *self.transport) {
            return Err(Error::InvalidState(Some("WebTransport mismatch".into())));
        }

        // Step 2. Set this.[[SendGroup]] to value.
        self.send_group.set(value);

        Ok(())
    }

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendorder>
    fn SendOrder(&self) -> i64 {
        // Step 1. Return this’s [[SendOrder]].
        self.send_order.get()
    }

    /// <https://w3c.github.io/webtransport/#dom-webtransportdatagramswritable-sendorder>
    fn SetSendOrder(&self, value: i64) {
        // Step 1. Set this.[[SendOrder]] to value.
        self.send_order.set(value);
    }
}
