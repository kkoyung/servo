/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::context::JSContext;
use js::rust::HandleObject;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_proto};
use servo_url::ServoUrl;

use crate::dom::bindings::error::{Error, Fallible};
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::codegen::Bindings::WebTransportBinding::{
    WebTransportMethods, WebTransportOptions, WebTransportCongestionControl,
};
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::USVString;
use crate::dom::bindings::trace::RootedTraceableBox;
use crate::dom::globalscope::GlobalScope;
use crate::dom::webtransport::webtransportsendgroup::WebTransportSendGroup;
use crate::dom::stream::readablestream::ReadableStream;

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
    /// <https://w3c.github.io/webtransport/#webtransport-constructor>
    fn Constructor(
        cx: &mut JSContext,
        global: &GlobalScope,
        proto: Option<HandleObject>,
        url: USVString,
        options: RootedTraceableBox<WebTransportOptions>,
    ) -> Fallible<DomRoot<WebTransport>> {
        // Step 1. Let baseURL be this’s relevant settings object’s API base URL.
        let base_url = global.api_base_url();

        // Step 2. Let url be the URL record resulting from parsing url with baseURL.
        // Step 3. If url is failure, throw a SyntaxError exception.
        let url = ServoUrl::parse_with_base(Some(&base_url), &url).or(Err(Error::Syntax(Some(
            "Failed to paring url with baseURL".into(),
        ))))?;

        // Step 4. If url’s scheme is not https, throw a SyntaxError exception.
        if url.scheme() != "https" {
            return Err(Error::Syntax(Some("URL's scheme is not https".into())));
        }

        // Step 5. If url’s fragment is not null, throw a SyntaxError exception.
        if !url.fragment().is_none() {
            return Err(Error::Syntax(Some("URL's fragment is not null".into())));
        }

        // Step 6. Let newConnection be "no" if options’s allowPooling is true; otherwise
        // "yes-and-dedicated".
        let new_connection = if options.allowPooling {
            "no"
        } else {
            "yes-and-dedicated"
        };

        // Step 7. Let serverCertificateHashes be options’s serverCertificateHashes.
        let server_certificate_hashes = &options.serverCertificateHashes;

        // Step 8. If newConnection is "no" and serverCertificateHashes is not empty, then throw a
        // NotSupportedError exception.
        if new_connection == "no" && !server_certificate_hashes.is_empty() {
            return Err(Error::NotSupported(Some(
                "newConnection is \"no\" and serverCertificateHashes is not empty".into(),
            )));
        }

        // Step 9. Let requireUnreliable be options’s requireUnreliable.
        let require_unreliable = options.requireUnreliable;

        // Step 10. Let congestionControl be options’s congestionControl.
        let mut congestion_control = options.congestionControl;

        // Step 11. If congestionControl is not "default", and the user agent does not support any
        // congestion control algorithms that optimize for congestionControl, as allowed by
        // [RFC9002] Section 7, then set congestionControl to "default".
        //
        // NOTE: Only support "default" for now.
        congestion_control = WebTransportCongestionControl::Default;

        // Step 12. Let protocols be options’s protocols.
        let protocols = &options.protocols;

        // TODO:
        // Step 13. If any of the values in protocols occur more than once, fail to match the
        // requirements for elements that comprise the value of the negotiated application protocol
        // as defined by the WebTransport protocol, or have an isomorphic encoded length of 0 or
        // exceeding 512, throw a SyntaxError exception. [WEB-TRANSPORT-OVERVIEW] Section 3.1.

        // Step 14. Let anticipatedConcurrentIncomingUnidirectionalStreams be options’s
        // anticipatedConcurrentIncomingUnidirectionalStreams.
        let anticipated_concurrent_incoming_unidirectional_streams =
            options.anticipatedConcurrentIncomingUnidirectionalStreams;

        // Step 15. Let anticipatedConcurrentIncomingBidirectionalStreams be options’s
        // anticipatedConcurrentIncomingBidirectionalStreams.
        let anticipated_concurrent_incoming_bidirectional_streams =
            options.anticipatedConcurrentIncomingBidirectionalStreams;

        // Step 16. Let datagramsReadableType be options’s datagramsReadableType.
        let datagrams_readable_type = options.datagramsReadableType;

        // Step 17. Let incomingDatagrams be a new ReadableStream.
        let incoming_datagram = ReadableStream::new_with_proto(cx, global, None);

        // TODO: Fill in the internal slot.
        // Step 18. Let transport be a newly constructed WebTransport object, with:
        // [[SendStreams]]
        //     an empty ordered set
        // [[ReceiveStreams]]
        //     an empty ordered set
        // [[IncomingBidirectionalStreams]]
        //     a new ReadableStream
        // [[IncomingUnidirectionalStreams]]
        //     a new ReadableStream
        // [[State]]
        //     "connecting"
        // [[Ready]]
        //     a new promise
        // [[Reliability]]
        //     "pending"
        // [[CongestionControl]]
        //     congestionControl
        // [[AnticipatedConcurrentIncomingUnidirectionalStreams]]
        //     anticipatedConcurrentIncomingUnidirectionalStreams
        // [[AnticipatedConcurrentIncomingBidirectionalStreams]]
        //     anticipatedConcurrentIncomingBidirectionalStreams
        // [[ResponseHeaders]]
        //     null
        // [[Protocol]]
        //     an empty string
        // [[Closed]]
        //     a new promise
        // [[Draining]]
        //     a new promise
        // [[Datagrams]]
        //     undefined
        // [[Session]]
        //     null
        // [[NewConnection]]
        //     newConnection
        // [[RequireUnreliable]]
        //     requireUnreliable
        let transport = WebTransport::new_with_proto(cx, global, proto);

        // // TODO: Step 19 - 25.
        //
        // // Step 26. Let client be transport’s relevant settings object.
        // let client = transport.global();
        //
        // // Step 27. Let origin be client’s origin.
        // let origin = global.origin();
        //
        // // Step 28. Let request be a new request whose URL is url, client is client, service-workers
        // // mode is "none", referrer is "no-referrer", mode is "webtransport", credentials mode is
        // // "omit", cache mode is "no-store", policy container is client’s policy container,
        // // destination is "", origin is origin, WebTransport-hash list is serverCertificateHashes
        // // and redirect mode is "error".
        // // Step 29. Set request’s method to "CONNECT", and set the method’s associated :protocol
        // // pseudo-header to "webtransport".
        // //
        // // TODO:
        // // - mode is "webtransport"
        // // - WebTransport-hash list is serverCertificateHashes
        // // - set the method’s associated :protocol pseudo-header to "webtransport"
        // let mut request = RequestBuilder::new(
        //     global.webview_id(),
        //     UrlWithBlobClaim::from_url_without_having_claimed_blob(url),
        //     Referrer::NoReferrer,
        // )
        // .with_global_scope(global)
        // .client(RequestClient {
        //     preloaded_resources: PreloadedResources::default(),
        //     policy_container: client.policy_container(),
        //     origin: Origin::Client,
        //     is_nested_browsing_context: client.is_nested_browsing_context(),
        //     insecure_requests_policy: client.insecure_requests_policy(),
        //     has_trustworthy_ancestor_origin: client.has_trustworthy_ancestor_origin(),
        // })
        // .service_workers_mode(ServiceWorkersMode::None)
        // .credentials_mode(CredentialsMode::Omit)
        // .cache_mode(CacheMode::NoCache)
        // .destination(Destination::None)
        // .origin(origin.immutable().clone())
        // .redirect_mode(RedirectMode::Error)
        // .method(Method::CONNECT);
        //
        // // Step 30. Let headers be a new Headers object filled with options["headers"].
        // let headers = Headers::new(cx, global);
        // // TODO: headers.fill(options.headers);
        //
        // // Step 31. Let requestHeaders be a new Headers object whose header list is request’s header
        // // list and guard is "request".
        // let request_headers = Headers::new(cx, global);
        // request_headers.set_headers(request.headers.clone());
        // request_headers.set_guard(Guard::Response);
        //
        // // Step 32. For each header of headers’s header list:
        // for (header_name, header_value) in headers.get_headers_list().iter() {
        //     // Step 32.1. If ascii lowercase header’s name is "wt-available-protocols", then throw a
        //     // TypeError.
        //     // NOTE: The string returned by http::header::HeaderName::as_str always be lower case.
        //     if header_name.as_str() == "wt-available-protocols" {
        //         return Err(Error::Type(
        //             c"Ascii lowercase header’s name is \"wt-available-protocols\"".into(),
        //         ));
        //     }
        //
        //     // Step 32.2. append header to requestHeaders.
        //     let header_name_bytes: &[u8] = header_name.as_ref();
        //     let header_value_bytes: &[u8] = header_value.as_bytes();
        //     request_headers.Append(
        //         ByteString::new(header_name_bytes.to_vec()),
        //         ByteString::new(header_value_bytes.to_vec()),
        //     )?;
        // }
        //
        // // TODO:
        // // Step 33. If protocols is not empty, set a structured field value with
        // // (WT-Available-Protocols, a structured header list whose members are the structured header
        // // string items in protocols in order) in request’s header list.
        //
        // // Step 34. Fetch request, with useParallelQueue set to true, and processResponse set to the
        // // following steps given a response:
        // // Step 34.1. Process a WebTransport fetch response with response and transport.
        // //
        // // NOTE: useParallelQueue is still missing in Servo
        // global.fetch(
        //     request,
        //     WebTransportFetchListener {},
        //     global.task_manager().networking_task_source().into(),
        // );

        // Step 35. Return transport.
        Ok(transport)
    }

    /// <https://w3c.github.io/webtransport/#dom-webtransport-createsendgroup>
    fn CreateSendGroup(&self, cx: &mut JSContext) -> DomRoot<WebTransportSendGroup> {
        // TODO:
        // Step 1. If this.[[State]] is "closed" or "failed", throw an InvalidStateError.

        // Step 2. Return the result of creating a WebTransportSendGroup with this.
        WebTransportSendGroup::create(cx, &self.global(), self)
    }
}
