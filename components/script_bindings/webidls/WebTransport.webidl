/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://w3c.github.io/webtransport/#web-transport
[Exposed=(Window,Worker), SecureContext, Pref="dom_webtransport_enabled"]
interface WebTransport {
  [Throws] constructor(USVString url, optional WebTransportOptions options = {});

  // Promise<WebTransportConnectionStats> getStats();
  // [NewObject] Promise<Uint8Array> exportKeyingMaterial(BufferSource label, BufferSource context, unsigned long outputLength);
  // readonly attribute Promise<undefined> ready;
  // readonly attribute WebTransportReliabilityMode reliability;
  // readonly attribute WebTransportCongestionControl congestionControl;
  // attribute [EnforceRange] unsigned short? anticipatedConcurrentIncomingUnidirectionalStreams;
  // attribute [EnforceRange] unsigned short? anticipatedConcurrentIncomingBidirectionalStreams;
  // [SameObject] readonly attribute Headers? responseHeaders;
  // readonly attribute DOMString protocol;

  // readonly attribute Promise<WebTransportCloseInfo> closed;
  // readonly attribute Promise<undefined> draining;
  // undefined close(optional WebTransportCloseInfo closeInfo = {});

  // readonly attribute WebTransportDatagramDuplexStream datagrams;

  // Promise<WebTransportBidirectionalStream> createBidirectionalStream(
  //     optional WebTransportSendStreamOptions options = {});
  /* a ReadableStream of WebTransportBidirectionalStream objects */
  // readonly attribute ReadableStream incomingBidirectionalStreams;

  // Promise<WebTransportSendStream> createUnidirectionalStream(
  //     optional WebTransportSendStreamOptions options = {});
  /* a ReadableStream of WebTransportReceiveStream objects */
  // readonly attribute ReadableStream incomingUnidirectionalStreams;
  WebTransportSendGroup createSendGroup();

  // static readonly attribute boolean supportsReliableOnly;
};

enum WebTransportReliabilityMode {
  "pending",
  "reliable-only",
  "supports-unreliable",
};

// https://w3c.github.io/webtransport/#web-transport-configuration
dictionary WebTransportHash {
  required DOMString algorithm;
  required BufferSource value;
};

dictionary WebTransportOptions {
  boolean allowPooling = false;
  boolean requireUnreliable = false;
  // FIXME: Codegen cannot coerce default dictionary value to type ByteStringSequenceSequenceOrByteStringByteStringRecord.
  // HeadersInit headers = {};
  sequence<WebTransportHash> serverCertificateHashes = [];
  WebTransportCongestionControl congestionControl = "default";
  [EnforceRange] unsigned short? anticipatedConcurrentIncomingUnidirectionalStreams = null;
  [EnforceRange] unsigned short? anticipatedConcurrentIncomingBidirectionalStreams = null;
  sequence<DOMString> protocols = [];
  ReadableStreamType datagramsReadableType;
};

enum WebTransportCongestionControl {
  "default",
  "throughput",
  "low-latency",
};
