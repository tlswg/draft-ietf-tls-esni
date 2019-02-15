---
title: Encrypted Server Name Indication for TLS 1.3
abbrev: TLS 1.3 SNI Encryption
docname: draft-ietf-tls-esni-latest
category: exp

ipr: trust200902
area: General
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: RTFM, Inc.
       email: ekr@rtfm.com

 -
       ins: K. Oku
       name: Kazuho Oku
       organization: Fastly
       email: kazuhooku@gmail.com

 -
       ins: N. Sullivan
       name: Nick Sullivan
       organization: Cloudflare
       email: nick@cloudflare.com

 -
       ins: C. A. Wood
       name: Christopher A. Wood
       organization: Apple, Inc.
       email: cawood@apple.com


normative:
  RFC1035:
  RFC2119:
  RFC6234:
  RFC7918:

informative:



--- abstract

This document defines a simple mechanism for encrypting the
Server Name Indication for TLS 1.3.

--- middle

# Introduction

DISCLAIMER: This is very early a work-in-progress design and has not
yet seen significant (or really any) security analysis. It should not
be used as a basis for building production systems.

Although TLS 1.3 {{!RFC8446}} encrypts most of the
handshake, including the server certificate, there are several other
channels that allow an on-path attacker to determine the domain name the
client is trying to connect to, including:

* Cleartext client DNS queries.
* Visible server IP addresses, assuming the the server is not doing
  domain-based virtual hosting.
* Cleartext Server Name Indication (SNI) {{!RFC6066}} in ClientHello messages.

DoH {{?I-D.ietf-doh-dns-over-https}} and DPRIVE {{?RFC7858}} {{?RFC8094}}
provide mechanisms for clients to conceal DNS lookups from network inspection,
and many TLS servers host multiple domains on the same IP address.
In such environments, SNI is an explicit signal used to determine the server's
identity. Indirect mechanisms such as traffic analysis also exist.

The TLS WG has extensively studied the problem of protecting SNI, but
has been unable to develop a completely generic
solution. {{?I-D.ietf-tls-sni-encryption}} provides a description
of the problem space and some of the proposed techniques. One of the
more difficult problems is "Do not stick out"
({{?I-D.ietf-tls-sni-encryption}}; Section 3.4): if only sensitive/private
services use SNI encryption, then SNI encryption is a signal that
a client is going to such a service. For this reason,
much recent work has focused on
concealing the fact that SNI is being protected. Unfortunately,
the result often has undesirable performance consequences, incomplete
coverage, or both.

The design in this document takes a different approach: it assumes
that private origins will co-locate with or hide behind a provider (CDN, app server,
etc.) which is able to activate encrypted SNI (ESNI) for all of the domains
it hosts. Thus, the use of encrypted SNI does not indicate that the
client is attempting to reach a private origin, but only that it is
going to a particular service provider, which the observer could
already tell from the IP address.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Overview

This document is designed to operate in one of two primary topologies
shown below, which we call "Shared Mode" and "Split Mode"

## Topologies

~~~~
                +---------------------+
                |                     |
                |   2001:DB8::1111    |
                |                     |
Client <----->  | private.example.org |
                |                     |
                | public.example.com  |
                |                     |
                +---------------------+
                        Server
~~~~
{: #shared-mode title="Shared Mode Topology"}

In Shared Mode, the provider is the origin server for all the domains
whose DNS records point to it and clients form a TLS connection directly
to that provider, which has access to the plaintext of the connection.

~~~~
                +--------------------+       +---------------------+
                |                    |       |                     |
                |   2001:DB8::1111   |       |   2001:DB8::EEEE    |
Client <------------------------------------>|                     |
                | public.example.com |       | private.example.com |
                |                    |       |                     |
                +--------------------+       +---------------------+
                  Client-Facing Server            Backend Server
~~~~
{: #split-mode title="Split Mode Topology"}

In Split Mode, the provider is *not* the origin server for private
domains. Rather the DNS records for private domains point to the provider,
but the provider's server just relays the connection back to the
backend server, which is the true origin server. The provider does
not have access to the plaintext of the connection. In principle,
the provider might not be the origin for any domains, but as
a practical matter, it is probably the origin for a large set of
innocuous domains, but is also providing protection for some private
domains. Note that the backend server can be an unmodified TLS 1.3
server.


## SNI Encryption

First, the provider publishes a public key and metadata which is used for SNI
encryption for all the domains for which it serves directly or indirectly (via
Split Mode). This document defines a publication mechanism using DNS, but other
mechanisms are also possible. In particular, if some of the clients of a private
server are applications rather than Web browsers, those applications might have
the public key and metadata preconfigured.

When a client wants to form a TLS connection to any of the domains
served by an ESNI-supporting provider, it sends an "encrypted_server_name"
extension, which contains the true extension encrypted under the
provider's public key. The provider can then decrypt the extension
and either terminate the connection (in Shared Mode) or forward
it to the backend server (in Split Mode).

# Publishing the SNI Encryption Key {#publishing-key}

SNI Encryption keys can be published in the DNS using the ESNIKeys
structure, defined below.

~~~~
    // Copied from TLS 1.3
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;

    struct {
        uint16 version;
        uint8 checksum[4];
        opaque public_name<1..2^16-1>;
        KeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
        uint16 padded_length;
        uint64 not_before;
        uint64 not_after;
        Extension extensions<0..2^16-1>;
    } ESNIKeys;
~~~~

version
: The version of the structure. For this specification, that value
SHALL be 0xff02. Clients MUST ignore any ESNIKeys structure with a
version they do not understand.
[[NOTE: This means that the RFC will presumably have a nonzero value.]]

checksum
: The first four (4) octets of the SHA-256 message digest {{RFC6234}}
of the ESNIKeys structure. For the purpose of computing the checksum, the
value of the "checksum" field MUST be set to zero.

public_name
: The name of the entity trusted to update these encryption keys.
This is used by the server in case there is a key mismatch or the
server has disabled ESNI.

keys
: The list of keys which can be used by the client to encrypt the SNI.
Every key being listed MUST belong to a different group.

padded_length
:
The length to pad the ServerNameList value to prior to encryption.
This value SHOULD be set to the largest ServerNameList the server
expects to support rounded up the nearest multiple of 16. If the
server supports wildcard names, it SHOULD set this value to 260.

not_before
: The moment when the keys become valid for use. The value is represented
as seconds from 00:00:00 UTC on Jan 1 1970, not including leap seconds.

not_after
: The moment when the keys become invalid. Uses the same unit as
not_before.

extensions
: A list of extensions that the client can take into consideration when
generating a Client Hello message. The format is defined in
{{RFC8446}}; Section 4.2. The purpose of the field is to
provide room for additional features in the future; this document does
not define any extension.

The semantics of this structure are simple: any of the listed keys may
be used to encrypt the SNI for the associated domain name.
The cipher suite list is orthogonal to the
list of keys, so each key may be used with any cipher suite.

This structure is placed in the RRData section of a TXT record
as a base64-encoded string. If this encoding exceeds the 255 octet
limit of TXT strings, it must be split across multiple concatenated
strings as per Section 3.1.3 of {{!RFC4408}}. Servers MAY supply
multiple ESNIKeys values, either of the same or of different versions.
This allows a server to support multiple versions at once.
If the server does not supply any ESNIKeys values with a version
known to the client, then the client MUST behave as if no
ESNIKeys were found.

The name of each TXT record MUST match the name composed
of \_esni and the query domain name. That is, if a client queries
example.com, the ESNI TXT Resource Record might be:

~~~
_esni.example.com. 60S IN TXT "..." "..."
~~~

Servers MUST ensure that if multiple A or AAAA records are returned for a
domain with ESNI support, all the servers pointed to by those records are
able to handle the keys returned as part of a ESNI TXT record for that domain.

Clients obtain these records by querying DNS for ESNI-enabled server domains.
Clients may initiate these queries in parallel alongside normal A or AAAA queries,
and SHOULD block TLS handshakes until they complete, perhaps by timing out.

In cases where the domain of the A or AAAA records being resolved do
not match the SNI Server Name, such as when {{!RFC7838}} is being used, the SNI
domain should be used for querying the ESNI TXT record.

Servers operating in Split Mode SHOULD have DNS configured to return
the same A (or AAAA) record for all ESNI-enabled servers they service. This yields
an anonymity set of cardinality equal to the number of ESNI-enabled server domains
supported by a given client-facing server. Thus, even with SNI encryption,
an attacker which can enumerate the set of ESNI-enabled domains supported
by a client-facing server can guess the correct SNI with probability at least
1/K, where K is the size of this ESNI-enabled server anonymity set. This probability
may be increased via traffic analysis or other mechanisms.

The "checksum" field provides protection against transmission errors,
including those caused by intermediaries such as a DNS proxy running on a
home router.

"not_before" and "not_after" fields represent the validity period of the
published ESNI keys. Clients MUST NOT use ESNI keys that was covered by an
invalid checksum or beyond the published period. If none of the ESNI keys
values are acceptable, the client SHOULD behave as if no ESNIKeys
were found.

Servers SHOULD set the Resource Record TTL small enough so that the
record gets discarded by the cache before the ESNI keys reach the end of
their validity period. Note that servers MAY need to retain the decryption key
for some time after "not_after", and will need to consider clock skew, internal
caches and the like, when selecting the "not_before" and "not_after" values.

Client MAY cache the ESNIKeys for a particular domain based on the TTL of the
Resource Record, but SHOULD NOT cache it based on the not_after value, to allow
servers to rotate the keys often and improve forward secrecy.

Note that the length of this structure MUST NOT exceed 2^16 - 1, as the
RDLENGTH is only 16 bits {{RFC1035}}.

# The "encrypted_server_name" extension {#esni-extension}

The encrypted SNI is carried in an "encrypted_server_name"
extension, defined as follows:

~~~
   enum {
       encrypted_server_name(0xffce), (65535)
   } ExtensionType;
~~~

For clients (in ClientHello), this extension contains the following
ClientEncryptedSNI structure:

~~~~
   struct {
       CipherSuite suite;
       KeyShareEntry key_share;
       opaque record_digest<0..2^16-1>;
       opaque encrypted_sni<0..2^16-1>;
   } ClientEncryptedSNI;
~~~~

suite
: The cipher suite used to encrypt the SNI.

key_share
: The KeyShareEntry carrying the client's public ephemeral key shared
used to derive the ESNI key.

record_digest
: A cryptographic hash of the ESNIKeys structure from which the ESNI
key was obtained, i.e., from the first byte of "checksum" to the end
of the structure.  This hash is computed using the hash function
associated with `suite`.

encrypted_sni
: The ClientESNIInner structure, AEAD-encrypted using cipher suite "suite" and
the key generated as described below.
{:br}

For servers (in EncryptedExtensions), this extension contains the following
structure:

~~~
   enum {
       esni_accept(0),
       esni_retry_request(1),
   } ServerESNIResponseType;

   struct {
       ServerESNIResponseType response_type;
       select (response_type) {
           case esni_accept:        uint8 nonce[16];
           case esni_retry_request: ESNIKeys retry_keys<1..2^16-1>;
       }
   } ServerEncryptedSNI;
~~~

response_type
: Indicates whether the server processed the client ESNI extension. (See
{{handle-server-response}} and {{server-behavior}}.}

nonce
: The contents of ClientESNIInner.nonce. (See {{client-behavior}}.)

retry_keys
: One or more ESNIKeys structures containing the keys that the client should use on
subsequent connections to encrypt the ClientESNIInner structure.

This protocol also defines the "esni_required" alert, which is sent by the
client when it offered an "encrypted_server_name" extension which was not
accepted by the server.

~~~~
   enum {
       esni_required(121),
   } AlertDescription;
~~~~

Finally, requirements in {{client-behavior}} and {{server-behavior}} require
implementations to track, alongside each PSK established by a previous
connection, whether the connection which this extension with the "esni_accept"
response type. If so, this is referred to as an "ESNI PSK".  Otherwise, it is a
"non-ESNI PSK". This may be implemented by adding a new field to client and
server session states.


## Client Behavior {#client-behavior}

### Sending an encrypted SNI {#send-esni}

In order to send an encrypted SNI, the client MUST first select one of
the server ESNIKeyShareEntry values and generate an (EC)DHE share in the
matching group. This share will then be sent to the server in the
"encrypted_sni" extension and used to derive the SNI encryption key. It does not affect the
(EC)DHE shared secret used in the TLS key schedule. It MUST also select
an appropriate cipher suite from the list of suites offered by the
server. If the client is unable to select an appropriate group or suite it SHOULD ignore that ESNIKeys value and MAY attempt to use another value provided by the server (recall that servers might provide multiple ESNIKeys in response to a ESNI TXT query).
The client MUST NOT send
encrypted SNI using groups or cipher suites not advertised by the server.

When offering an encrypted SNI, the client MUST NOT offer to resume any non-ESNI
PSKs. It additionally MUST NOT offer to resume any sessions for TLS 1.2 or
below.

Let Z be the DH shared secret derived from a key share in ESNIKeys and the
corresponding client share in ClientEncryptedSNI.key_share. The SNI encryption key is
computed from Z as follows:

~~~~
   Zx = HKDF-Extract(0, Z)
   key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
   iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
~~~~

where ESNIContents is as specified below and Hash is the hash function
associated with the HKDF instantiation.

~~~
   struct {
       opaque record_digest<0..2^16-1>;
       KeyShareEntry esni_key_share;
       Random client_hello_random;
   } ESNIContents;
~~~

The client then creates a ClientESNIInner structure:

~~~~
   struct {
       ServerNameList sni;
       opaque zeros[ESNIKeys.padded_length - length(sni)];
   } PaddedServerNameList;

   struct {
       uint8 nonce[16];
       PaddedServerNameList realSNI;
   } ClientESNIInner;
~~~~
nonce
: A random 16-octet value to be echoed by the server in the
"encrypted_server_name" extension.

sni
: The true SNI, that is, the ServerNameList that would have been sent in the
plaintext "server_name" extension.

zeros
: Zero padding whose length makes the serialized PaddedServerNameList
struct have a length equal to ESNIKeys.padded_length.

This value consists of the serialized ServerNameList from the "server_name" extension,
padded with enough zeroes to make the total structure ESNIKeys.padded_length
bytes long. The purpose of the padding is to prevent attackers
from using the length of the "encrypted_server_name" extension
to determine the true SNI. If the serialized ServerNameList is
longer than ESNIKeys.padded_length, the client MUST NOT use
the "encrypted_server_name" extension.

The ClientEncryptedSNI.encrypted_sni value is then computed using the usual
TLS 1.3 AEAD:

~~~~
    encrypted_sni = AEAD-Encrypt(key, iv, ClientHello.KeyShareClientHello, ClientESNIInner)
~~~~

Where ClientHello.KeyShareClientHello is the body of the extension but
not including the extension header. Including
ClientHello.KeyShareClientHello in the AAD of AEAD-Encrypt binds the
ClientEncryptedSNI value to the ClientHello and prevents cut-and-paste
attacks.

Note: future extensions may end up reusing the server's ESNIKeyShareEntry
for other purposes within the same message (e.g., encrypting other
values). Those usages MUST have their own HKDF labels to avoid
reuse.

[[OPEN ISSUE: If in the future you were to reuse these keys for
0-RTT priming, then you would have to worry about potentially
expanding twice of Z_extracted. We should think about how
to harmonize these to make sure that we maintain key separation.]]

This value is placed in an "encrypted_server_name" extension.

The client MUST place the value of ESNIKeys.public_name in the "server_name"
extension. (This is required for technical conformance with {{!RFC7540}};
Section 9.2.)

### Handling the server response {#handle-server-response}

If the server negotiates TLS 1.3 or above and provides an
"encrypted_server_name" extension in EncryptedExtensions, the client
then processes the extension's "response_type" field:

- If the value is "esni_accept", the client MUST check that the extension's
  "nonce" field matches ClientESNIInner.nonce and otherwise abort the
  connection with an "illegal_parameter" alert. The client then proceeds
  with the connection as usual, verifying the certificate against the desired
  name.

- If the value is "esni_retry_request", the client proceeds with the handshake,
  verifying the certificate against ESNIKeys.public_name as described in
  {{verify-public-name}}. If verification or the handshake fails, the client
  MUST return a failure to calling application. It MUST NOT use the retry keys
  as described below.

  Otherwise, when the handshake completes successfully with the public name
  verified, the client MUST abort the connection with an "esni_required" alert.
  The client can then regard the ESNI keys as securely replaced by the server.
  It processes the "retry_keys" field from the server's "encrypted_server_name"
  extension. If one of the values used a version known to the client, the client
  SHOULD retry the handshake with a new transport connection, using that value
  to encrypt the SNI. If no value is applicable, the client SHOULD retry with
  ESNI disabled.

  These retry keys may only be applied to the retry connection. The client MUST
  continue to use the previously cached keys for subsequent connections. This
  avoids introducing pinning concerns or a tracking vector, should a malicious
  server present client-specific retry keys to identify clients.

- If the field contains any other value, the client MUST abort the connection
  with an "illegal_parameter" alert.

If the server negotiates an earlier version of TLS, or if it does not
provide an "encrypted_server_name" extension in EncryptedExtensions, the
client proceeds with the handshake, verifying the certificate against
ESNIKeys.public_name as described in {{verify-public-name}}. The client MUST
NOT enable the False Start optimization {{RFC7918}} for this handshake. If
verification or the handshake fails, the client MUST return a failure to the
calling application. It MUST NOT treat this as a signal to disable ESNI as
described below.

Otherwise, when the handshake completes successfully with the public name
verified, the client MUST abort the connection with an "esni_required" alert.
The client can then regard ESNI as securely disabled by the server. It SHOULD
retry the handshake with a new transport connection and ESNI disabled.

[[TODO: Key replacement is significantly less scary than saying that ESNI-naive
  servers bounce ESNI off. Is it worth defining a strict mode toggle in the ESNI
  keys, for a deployment to indicate it is ready for that? ]]

Clients SHOULD implement a limit on retries caused by "esni_retry_request" or
servers which do not acknowledge the "encrypted_server_name" extension. If the
client does not retry in either scenario, it MUST report an error to the
calling application.

### Verifying against the public name {#verify-public-name}

When the server cannot decrypt or does not process the "encrypted_server_name"
extension, it continues with the handshake using the cleartext "server_name"
extension instead (see {{server-behavior}}). Clients that offer ESNI then
verify the certificate with the public name, as follows:

- If the server resumed a session or did not negotiate certificate-based
  authentication, the client MUST abort the connection with an illegal_parameter
  alert. This case is invalid because {{send-esni}} requires the client
  to only offer ESNI-established sessions, and {{server-behavior}} requires
  the server to decline ESNI-established sessions if it did not accept ESNI.

- The client MUST verify that the certificate is valid for ESNIKeys.public_name.
  If invalid, it MUST abort the connection with the appropriate alert.

- If the server requests a client certificate, the client MUST respond with an
  empty Certificate message, denoting no client certificate.

Note that verifying a connection for the public name does not verify it for the
origin. The TLS implementation MUST NOT report such connections as successful to
the application. It additionally MUST ignore all session tickets and session IDs
presented by the server. These connections are only used to trigger retries, as
described in {{handle-server-response}}. This may be implemented, for instance, by
reporting a failed connection with a dedicated error code.

## Client-Facing Server Behavior {#server-behavior}

Upon receiving an "encrypted_server_name" extension, the client-facing
server MUST check that it is able to negotiate TLS 1.3 or greater. If not,
it MUST abort the connection with a "handshake_failure" alert.

If the ClientEncryptedSNI.record_digest value does not match the
cryptographic hash of any known ESNIKeys structure, it MUST ignore the
extension and proceed with the connection, with the following added
behavior:

- It MUST include the "encrypted_server_name" extension in
  EncryptedExtensions message with the "response_type" field set to
  "esni_retry_requested" and the "retry_keys" field set to one or more
  ESNIKeys structures with up-to-date keys. Servers MAY supply multiple
  ESNIKeys values of different versions. This allows a server to support
  multiple versions at once.

- The server MUST ignore all PSK identities in the ClientHello which correspond
  to ESNI PSKs. ESNI PSKs offered by the client are associated with the ESNI
  name. The server was unable to decrypt then ESNI name, so it should not resume
  them when using the cleartext SNI name. This restriction allows a client to
  reject resumptions in {{verify-public-name}}.

If the ClientEncryptedSNI.record_digest value does match the cryptographic
hash of a known ESNIKeys, the server performs the following checks:

- If the ClientEncryptedSNI.key_share group does not match one in the ESNIKeys.keys,
  it MUST abort the connection with an "illegal_parameter" alert.

- If the length of the "encrypted_server_name" extension is
  inconsistent with the advertised padding length (plus AEAD
  expansion) the server MAY abort the connection with an
  "illegal_parameter" alert without attempting to decrypt.

Assuming these checks succeed, the server then computes K_sni
and decrypts the ServerName value. If decryption fails, the server
MUST abort the connection with a "decrypt_error" alert.

If the decrypted value's length is different from
the advertised ESNIKeys.padded_length or the padding consists of
any value other than 0, then the server MUST abort the
connection with an illegal_parameter alert. Otherwise, the
server uses the PaddedServerNameList.sni value as if it were
the "server_name" extension. Any actual "server_name" extension is
ignored, which also means the server MUST NOT send the "server_name"
extension to the client.

Upon determining the true SNI, the client-facing server then either
serves the connection directly (if in Shared Mode), in which case
it executes the steps in the following section, or forwards
the TLS connection to the backend server (if in Split Mode). In
the latter case, it does not make any changes to the TLS
messages, but just blindly forwards them.

## Shared Mode Server Behavior

A server operating in Shared Mode uses PaddedServerNameList.sni as
if it were the "server_name" extension to finish the handshake. It
SHOULD pad the Certificate message, via padding at the record layer,
such that its length equals the size of the largest possible Certificate
(message) covered by the same ESNI key. Moreover, the server MUST
include the "encrypted_server_name" extension in EncryptedExtensions
with the "response_type" field set to "esni_accept" and the "nonce"
field set to the decrypted PaddedServerNameList.nonce value from the client
"encrypted_server_name" extension.

If the server sends a NewSessionTicket message, the corresponding ESNI PSK MUST
be ignored by all other servers in the deployment when not negotiating ESNI,
including servers which do not implement this specification. This may be
implemented by adding a new field to the server session state which earlier
implementations cannot parse.

This restriction provides robustness for rollbacks (see {{misconfiguration}}).

## Split Mode Server Behavior {#backend-server-behavior}

In Split Mode, the backend server must know PaddedServerNameList.nonce
to echo it back in EncryptedExtensions and complete the handshake.
{{communicating-sni}} describes one mechanism for sending both
PaddedServerNameList.sni and ClientESNIInner.nonce to the backend
server. Thus, backend servers function the same as servers operating
in Shared Mode.

As in Shared Mode, if the backend server sends a NewSessionTicket message, the
corresponding ESNI PSK MUST be ignored by other servers in the deployment when
not negotiating ESNI, including servers which do not implement this
specification.

# Compatibility Issues

Unlike most TLS extensions, placing the SNI value in an ESNI extension
is not interoperable with existing servers, which expect the value in
the existing cleartext extension. Thus server operators SHOULD ensure
servers understand a given set of ESNI keys before advertising them.
Additionally, servers SHOULD retain support for any
previously-advertised keys for the duration of their validity.

However, in more complex deployment scenarios, this may be difficult
to fully guarantee. Thus this protocol was designed to be robust in case
of inconsistencies between systems that advertise ESNI keys and servers, at the
cost of extra round-trips due to a retry. Two specific scenarios are detailed
below.

## Misconfiguration and Deployment Concerns {#misconfiguration}

It is possible for ESNI advertisements and servers to become inconsistent. This
may occur, for instance, from DNS misconfiguration, caching issues, or an
incomplete rollout in a multi-server deployment. This may also occur if a server
loses its ESNI keys, or if a deployment of ESNI must be rolled back on the
server.

The retry mechanism repairs most such inconsistencies. If server and advertised keys mismatch,
the server will respond with esni_retry_requested. If the server does not understand the
"encrypted_server_name" extension at all, it will ignore it as required by {{RFC8446}};
Section 4.1.2. Provided the server can present a certificate valid for the public name,
the client can safely retry with updated settings, as described in {{handle-server-response}}.

If the public name does not verify or the retry fails, the client SHOULD NOT
fall back to cleartext SNI, as this allows a network attacker to disclose the SNI.
They MAY attempt to use another server from the DNS results, if one is provided.

## Middleboxes

A more serious problem is MITM proxies which do not support this
extension. {{RFC8446}}; Section 9.3 requires that
such proxies remove any extensions they do not understand. The handshake will
then present a certificate based on the public name, without echoing the
"encrypted_server_name" extension to the client.

Depending on whether the client is configured to accept the proxy's certificate
as authoritative for the public name, this may trigger the retry logic described
in {{handle-server-response}} or result in a connection failure. A proxy which
is not authoritative for the public name cannot forge a signal to disable ESNI.

A non-conformant MITM proxy which instead forwards the ESNI extension,
substituting its own KeyShare value, will result in
the client-facing server recognizing the key, but failing to decrypt
the SNI. This causes a hard failure. Clients SHOULD NOT attempt to repair the
connection in this case.

# Security Considerations

## Why is cleartext DNS OK? {#cleartext-dns}

In comparison to {{?I-D.kazuho-protected-sni}}, wherein DNS Resource
Records are signed via a server private key, ESNIKeys have no
authenticity or provenance information. This means that any attacker
which can inject DNS responses or poison DNS caches, which is a common
scenario in client access networks, can supply clients with fake
ESNIKeys (so that the client encrypts SNI to them) or strip the
ESNIKeys from the response. However, in the face of an attacker that
controls DNS, no SNI encryption scheme can work because the attacker
can replace the IP address, thus blocking client connections, or
substituting a unique IP address which is 1:1 with the DNS name that
was looked up (modulo DNS wildcards). Thus, allowing the ESNIKeys in
the clear does not make the situation significantly worse.

Clearly, DNSSEC (if the client validates and hard fails) is a defense against
this form of attack, but DoH/DPRIVE are also defenses against DNS attacks
by attackers on the local network, which is a common case where SNI is
desired.
Moreover, as noted in the introduction, SNI encryption is less useful
without encryption of DNS queries in transit via DoH or DPRIVE mechanisms.

## Comparison Against Criteria

{{?I-D.ietf-tls-sni-encryption}} lists several requirements for SNI
encryption. In this section, we re-iterate these requirements and assess
the ESNI design against them.

### Mitigate against replay attacks

Since the SNI encryption key is derived from a (EC)DH operation
between the client's ephemeral and server's semi-static ESNI key, the ESNI
encryption is bound to the Client Hello. It is not possible for
an attacker to "cut and paste" the ESNI value in a different Client
Hello, with a different ephemeral key share, as the terminating server
will fail to decrypt and verify the ESNI value.

### Avoid widely-deployed shared secrets

This design depends upon DNS as a vehicle for semi-static public key distribution.
Server operators may partition their private keys however they see fit provided
each server behind an IP address has the corresponding private key to decrypt
a key. Thus, when one ESNI key is provided, sharing is optimally bound by the number
of hosts that share an IP address. Server operators may further limit sharing
by sending different Resource Records containing ESNIKeys with different keys
using a short TTL.

### Prevent SNI-based DoS attacks

This design requires servers to decrypt ClientHello messages with ClientEncryptedSNI
extensions carrying valid digests. Thus, it is possible for an attacker to force
decryption operations on the server. This attack is bound by the number of
valid TCP connections an attacker can open.

### Do not stick out

As more clients enable ESNI support, e.g., as normal part of Web browser
functionality, with keys supplied by shared hosting providers, the presence
of ESNI extensions becomes less suspicious and part of common or predictable
client behavior. In other words, if all Web browsers start using ESNI,
the presence of this value does not signal suspicious behavior to passive
eavesdroppers.

### Forward secrecy

This design is not forward secret because the server's ESNI key is static.
However, the window of exposure is bound by the key lifetime. It is
RECOMMENDED that servers rotate keys frequently.

### Proper security context

This design permits servers operating in Split Mode to forward connections
directly to backend origin servers, thereby avoiding unnecessary MiTM attacks.

### Split server spoofing

Assuming ESNIKeys retrieved from DNS are validated, e.g., via DNSSEC or fetched
from a trusted Recursive Resolver, spoofing a server operating in Split Mode
is not possible. See {{cleartext-dns}} for more details regarding cleartext
DNS.

Validating the ESNIKeys structure additionally validates the public name. This
validates any retry signals from the server because the client validates the server
certificate against the public name before retrying.

### Supporting multiple protocols

This design has no impact on application layer protocol negotiation. It may affect
connection routing, server certificate selection, and client certificate verification.
Thus, it is compatible with multiple protocols.

## Misrouting

Note that the backend server has no way of knowing what the SNI was,
but that does not lead to additional privacy exposure because the
backend server also only has one identity. This does, however, change
the situation slightly in that the backend server might previously have
checked SNI and now cannot (and an attacker can route a connection
with an encrypted SNI to any backend server and the TLS connection will
still complete).  However, the client is still responsible for
verifying the server's identity in its certificate.

[[TODO: Some more analysis needed in this case, as it is a little
odd, and probably some precise rules about handling ESNI and no
SNI uniformly?]]

# IANA Considerations

## Update of the TLS ExtensionType Registry

IANA is requested to create an entry, encrypted_server_name(0xffce),
in the existing registry for ExtensionType (defined in
{{!RFC8446}}), with "TLS 1.3" column values being set to
"CH, EE", and "Recommended" column being set to "Yes".

## Update of the TLS Alert Registry

IANA is requested to create an entry, esni_required(121) in the
existing registry for Alerts (defined in {{!RFC8446}}), with the
"DTLS-OK" column being set to "Y".

## Update of the DNS Underscore Global Scoped Entry Registry

IANA is requested to create an entry in the DNS Underscore Global
Scoped Entry Registry (defined in {{!I-D.ietf-dnsop-attrleaf}}) with the
"RR Type" column value being set to "TXT", the "_NODE NAME" column
value being set to "_esni", and the "Reference" column value being set
to this document.

--- back


# Communicating SNI and Nonce to Backend Server {#communicating-sni}

When operating in Split Mode, backend servers will not have access
to PaddedServerNameList.sni or ClientESNIInner.nonce without
access to the ESNI keys or a way to decrypt ClientEncryptedSNI.encrypted_sni.

One way to address this for a single connection, at the cost of having
communication not be unmodified TLS 1.3, is as follows.
Assume there is a shared (symmetric) key between the
client-facing server and the backend server and use it to AEAD-encrypt Z
and send the encrypted blob at the beginning of the connection before
the ClientHello. The backend server can then decrypt ESNI to recover
the true SNI and nonce.

Another way for backend servers to access the true SNI and nonce is by the
client-facing server sharing the ESNI keys.

# Alternative SNI Protection Designs

Alternative approaches to encrypted SNI may be implemented at the TLS or
application layer. In this section we describe several alternatives and discuss
drawbacks in comparison to the design in this document.

## TLS-layer

### TLS in Early Data

In this variant, TLS Client Hellos are tunneled within early data payloads
belonging to outer TLS connections established with the client-facing server. This
requires clients to have established a previous session -— and obtained PSKs —- with
the server. The client-facing server decrypts early data payloads to uncover Client Hellos
destined for the backend server, and forwards them onwards as necessary. Afterwards, all
records to and from backend servers are forwarded by the client-facing server -- unmodified.
This avoids double encryption of TLS records.

Problems with this approach are: (1) servers may not always be able to
distinguish inner Client Hellos from legitimate application data, (2) nested 0-RTT
data may not function correctly, (3) 0-RTT data may not be supported --
especially under DoS -- leading to availability concerns, and (4) clients must bootstrap
tunnels (sessions), costing an additional round trip and potentially revealing the SNI
during the initial connection. In contrast, encrypted SNI protects the SNI in a distinct
Client Hello extension and neither abuses early data nor requires a bootstrapping connection.

### Combined Tickets

In this variant, client-facing and backend servers coordinate to produce "combined tickets"
that are consumable by both. Clients offer combined tickets to client-facing servers.
The latter parse them to determine the correct backend server to which the Client Hello
should be forwarded. This approach is problematic due to non-trivial coordination between
client-facing and backend servers for ticket construction and consumption. Moreover,
it requires a bootstrapping step similar to that of the previous variant. In contrast,
encrypted SNI requires no such coordination.

## Application-layer

### HTTP/2 CERTIFICATE Frames

In this variant, clients request secondary certificates with CERTIFICATE_REQUEST HTTP/2
frames after TLS connection completion. In response, servers supply certificates via TLS
exported authenticators {{!I-D.ietf-tls-exported-authenticator}} in CERTIFICATE frames.
Clients use a generic SNI for the underlying client-facing server TLS connection.
Problems with this approach include: (1) one additional round trip before peer
authentication, (2) non-trivial application-layer dependencies and interaction,
and (3) obtaining the generic SNI to bootstrap the connection. In contrast, encrypted
SNI induces no additional round trip and operates below the application layer.


# Total Client Hello Encryption

The design described here only provides encryption for the SNI, but
not for other extensions, such as ALPN. Another potential design
would be to encrypt all of the extensions using the same basic
structure as we use here for ESNI. That design has the following
advantages:

- It protects all the extensions from ordinary eavesdroppers
- If the encrypted block has its own KeyShare, it does not
  necessarily require the client to use a single KeyShare,
  because the client's share is bound to the SNI by the
  AEAD (analysis needed).

It also has the following disadvantages:

- The client-facing server can still see the other extensions. By
  contrast we could introduce another EncryptedExtensions
  block that was encrypted to the backend server and not
  the client-facing server.
- It requires a mechanism for the client-facing server to provide the
  extension-encryption key to the backend server (as in {{communicating-sni}}
  and thus cannot be used with an unmodified backend server.
- A conformant middlebox will strip every extension, which might
  result in a ClientHello which is just unacceptable to the server
  (more analysis needed).

# Acknowledgements

This document draws extensively from ideas in {{?I-D.kazuho-protected-sni}}, but
is a much more limited mechanism because it depends on the DNS for the
protection of the ESNI key. Richard Barnes, Christian Huitema, Patrick McManus,
Matthew Prince, Nick Sullivan, Martin Thomson, and Chris Wood also provided
important ideas.


