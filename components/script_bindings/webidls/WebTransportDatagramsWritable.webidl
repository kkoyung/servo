/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://w3c.github.io/webtransport/#webtransportdatagramswritable
[Exposed=(Window,Worker), SecureContext, /* Transferable */, Pref="dom_webtransport_enabled"]
interface WebTransportDatagramsWritable : WritableStream {
  [Throws] attribute WebTransportSendGroup? sendGroup;
  attribute long long sendOrder;
};
