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
  I-D.ietf-tls-grease:
  SNIExtensibilityFailed:
    title: Accepting that other SNI name types will never work
    target: https://mailarchive.ietf.org/arch/msg/tls/1t79gzNItZd71DwwoaqcQQ_4Yxc


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
when, and only when, they appear in all capitals, as shown here. All TLS notation
comes from {{RFC8446}}; Section 3.

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
and the provider's server relays the connection back to the
backend server, which is the true origin server. The provider does
not have access to the plaintext of the connection.

## SNI Encryption

SNI encryption requires that each provider publish a public key and
metadata which is used for SNI encryption for all the domains for
which it serves directly or indirectly (via Split Mode). This document
defines the format of the SNI encryption public key and metadata,
referred to as an ESNI configuration, and delegates DNS publication
details to {{!HTTPSSVC=I-D.nygren-dnsop-svcb-httpssvc}}, though other
delivery mechanisms are possible. In particular, if some of the
clients of a private server are applications rather than Web browsers,
those applications might have the public key and metadata
preconfigured.

When a client wants to form a TLS connection to any of the domains
served by an ESNI-supporting provider, it constructs a ClientHello in
the regular fashion containing the true SNI value (ClientHelloInner)
and then encrypts it using the public key for the provider.  It then
constructs a new ClientHello (ClientHelloOuter) with an innocuous SNI
(and potentially innocuous versions of other extensions such as ALPN
{{?RFC7301}}) and containing the encrypted ClientHelloInner as an
extension. It sends ClientHelloOuter to the server.

Upon receiving ClientHelloOuter, the server can then decrypt
ClientHelloInner and either terminate the connection (in Shared Mode)
or forward it to the backend server (in Split Mode).


# Encrypted SNI Configuration {#esni-configuration}

SNI Encryption configuration information is conveyed with the following
ESNIConfig structure.

~~~~
    // Copied from TLS 1.3
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;

    struct {
        uint16 version;
        opaque public_name<1..2^16-1>;
        KeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
        uint16 maximum_name_length;
        Extension extensions<0..2^16-1>;
    } ESNIConfig;
~~~~

The ESNIConfig structure contains the following fields:

version
: The version of the structure. For this specification, that value
SHALL be 0xff03. Clients MUST ignore any ESNIConfig structure with a
version they do not understand.
[[NOTE: This means that the RFC will presumably have a nonzero value.]]

public_name
: The non-empty name of the entity trusted to update these encryption keys.
This is used to repair misconfigurations, as described in
{{handle-server-response}}.

keys
: The list of keys which can be used by the client to encrypt the SNI.
Every key being listed MUST belong to a different group.

maximum_name_length
: the largest name the server expects to support
rounded up the nearest multiple of 16. If the server supports
arbitrary wildcard names, it SHOULD set this value to
256. Clients SHOULD reject ESNIConfig as invalid if maximum_name_length is
greater than 256.

extensions
: A list of extensions that the client can take into consideration when
generating a Client Hello message. The format is defined in
{{RFC8446}}; Section 4.2. The purpose of the field is to
provide room for additional features in the future. An extension
may be tagged as mandatory by using an extension type codepoint with
the high order bit set to 1. A client which receives a mandatory extension
they do not understand must reject the ESNIConfig content.

Any of the listed keys in the ESNIConfig value may
be used to encrypt the SNI for the associated domain name.
The cipher suite list is orthogonal to the
list of keys, so each key may be used with any cipher suite.
Clients MUST parse the extension list and check for unsupported
mandatory extensions. If an unsupported mandatory extension is
present, clients MUST reject the ESNIConfig value.

# The "encrypted_client_hello" extension {#encrypted-client-hello}

The encrypted ClientHelloInner is carried in an "encrypted_client_hello"
extension, defined as follows:

~~~
   enum {
       encrypted_client_hello(TBD), (65535)
   } ExtensionType;
~~~

For clients (in ClientHello), this extension contains the following
ClientEncryptedSNI structure:

~~~~
   struct {
       CipherSuite suite;
       KeyShareEntry key_share;
       opaque record_digest<0..2^16-1>;
       opaque encrypted_ch<0..2^16-1>;
   } ClientEncryptedCH;
~~~~

suite
: The cipher suite used to encrypt ClientHelloInner.

key_share
: The KeyShareEntry carrying the client's public ephemeral key share
used to derive the ESNI key.

record_digest
: A cryptographic hash of the ESNIConfig structure from which the ESNI
key was obtained, i.e., from the first byte of "version" to the end
of the structure.  This hash is computed using the hash function
associated with `suite`.

encrypted_sni
: The serialized ClientHelloInner structure, AEAD-encrypted using
cipher suite "suite" and the key generated as described below.
{:br}


If the server accepts ESNI, then does not send this extension.
If it rejects ESNI, then it sends the following structure in
EncryptedExtensions:

~~~
   struct {
       ESNIConfig retry_keys<1..2^16-1>;
   } ServerEncryptedCH;
~~~

retry_keys
: One or more ESNIConfig structures containing the keys that the client should use on
subsequent connections to encrypt the ClientESNIInner structure.

This protocol also defines the "esni_required" alert, which is sent by the
client when it offered an "encrypted_server_name" extension which was not
accepted by the server.


# The "esni_nonce" extension {#esni-nonce}

When using ESNI, the client MUST also add an extension of type
"esni_nonce" to the ClientHelloInner (but not to the outer
ClientHello).

The encrypted SNI is carried in an "encrypted_server_name"
extension, defined as follows:

~~~
   enum {
       esni_nonce(0xffce), (65535)
   } ExtensionType;

   struct {
       uint8 nonce[16];
   } ESNINonce;
~~~~

nonce
: A random 16-octet value generated by the client and echoed by the
server.

Finally, requirements in {{client-behavior}} and {{server-behavior}} require
implementations to track, alongside each PSK established by a previous
connection, whether the connection negotiated this extension with the
"esni_accept" response type. If so, this is referred to as an "ESNI PSK".
Otherwise, it is a "non-ESNI PSK". This may be implemented by adding a new field
to client and server session states.

## Incorporating Outer Extensions {#outer-extensions}

Some TLS 1.3 extensions can be quite large
and having them both in the inner and outer ClientHello wil lead to
a very large overall size. One particularly pathological example
is "key_share" with post-quantum algorithms. In order to reduce
the impact of duplicated extensions, the client may use the
"outer_extension" extension.

~~~
   enum {
       esni_extension(TBD), (65535)
   } ExtensionType;

   struct {
       ExtensionType extension;
       uint8 hash<32..255>;
   } OuterExtension;
~~~~

This extension MUST only be used in ClientHelloInner and contains
a digest of the corresponding extension in ClientHelloOuter.
When sending ClientHello, the client first computes ClientHelloInner,
including the PSK binders, and then MAY substitute any extensions
which it knows will be duplicated in ClientHelloOuter with
the corresponding "outer_extension". The hash value is computed
over the entire extension, including the type and length field
and uses the same hash as for the KDF used to encrypt ClienHelloInner.
This process is reversed by client-facing server upon receipt.

Clients SHOULD only use this mechanism for extensions which are
large. All other extensions SHOULD appear in both ClientHelloInner
and ClientHelloOuter even if they have identical values.

Multiple "outer_extension" extensions MAY appear in a ClientHelloInner
(this is a violation of normal TLS rules, but the resulting ClientHelloInner
is never processed directly). However, there MUST NOT be
multiple "outer_extension" extensions with the same extension code point.


# Client Behavior {#client-behavior}

## Sending an encrypted ClientHello {#send-esni}

In order to send an encrypted SNI, the client MUST first generate its
ClientHelloInner value. In addition to the normal values, ClientHelloInner
MUST also contain:

 - an "esni_nonce" extension
 - a TLS padding {{!RFC7685}}. This SHOULD contain X bytes of padding
   where X + the actual server name is equal to ESNIConfig.maximum_name_length

Then, the client MUST select one of the server ESNIKeyShareEntry
values and generate an (EC)DHE share in the matching group. This share
will then be sent to the server in the "encrypted_client_hello"
extension and used to derive the SNI encryption key. It does not
affect the (EC)DHE shared secret used in the TLS key schedule. The
client MUST also select an appropriate cipher suite from the list of
suites offered by the server. If the client is unable to select an
appropriate group or suite it SHOULD ignore that ESNIConfig value and
MAY attempt to use another value provided by the server. The client
MUST NOT send encrypted SNI using groups or cipher suites not
advertised by the server.

When offering an encrypted SNI, the client MUST NOT offer to resume any non-ESNI
PSKs. It additionally MUST NOT offer to resume any sessions for TLS 1.2 or
below.

Let Z be the DH shared secret derived from a key share in ESNIConfig and the
corresponding client share in ClientEncryptedSNI.key_share. The SNI encryption key is
computed from Z as follows:

~~~~
   Zx = HKDF-Extract(0, Z)
   key = HKDF-Expand-Label(Zx, KeyLabel, ClientHelloOuter.Random, key_length)
   iv = HKDF-Expand-Label(Zx, IVLabel, ClientHelloOuter.Random, iv_length)
~~~~

Where the Hash for HKDF is the hash function associated with the HKDF
instantiation. The salt argument for HKDF-Extract is a string
consisting of Hash.length bytes set to zeros. For a client's first
ClientHello, KeyLabel = "esni key" and IVLabel = "esni iv", whereas
for a client's second ClientHello, sent in response to a
HelloRetryRequest, KeyLabel = "hrr esni key" and IVLabel = "hrr esni
iv". (This label variance is done to prevent nonce re-use since the
client's ESNI key share, and thus the value of Zx, does not change
across ClientHello retries.)

[[TODO: label swapping fixes a bug in the spec, though this may not be
the best way to deal with HRR. See https://github.com/tlswg/draft-ietf-tls-esni/issues/121
and https://github.com/tlswg/draft-ietf-tls-esni/pull/170 for more details.]]

The client MAY replace any large, duplicated, extensions in ClientHelloInner
with the corresponding "outer_extensions" extension, as described in
{{outer-extensions}}.

The encrypted ClientHello value is then computed as:

~~~~
    encrypted_sni = AEAD-Encrypt(key, iv, "", ClientHelloIInner)
~~~~

[[OPEN ISSUE: If in the future you were to reuse these keys for
0-RTT priming, then you would have to worry about potentially
expanding twice of Zx We should think about how
to harmonize these to make sure that we maintain key separation.]]

Finally, the client MUST generate a ClientHelloOuter message
containing the "encrypted_client_hello" extension with the values as
indicated above. The client MUST place the value of
ESNIConfig.public_name in the "server_name" extension. The remaining
contents of the ClientHelloOuter MAY be identical to those in
ClientHelloInner but MAY also differ.  The ClientHelloOuter MUST NOT
contain a "cached_info" extension {{!RFC7924}} with a CachedObject
entry whose CachedInformationType is "cert", since this indication
would divulge the true server name.

## Handling the server response {#handle-server-response}

As described in {{server-behavior}}, the server MAY either accept ESNI
and use ClientHelloInner or reject it and use ClientHelloOuter. However,
there is no indication in ServerHello of which one the server has done
and the client must therefore use trial decryption in order to determine
this. 

### Accepted ESNI

If the server used ClientHelloInner, the client proceeds with the
connection as usual, authenticating the connection for the origin
server.

### Rejected ESNI

If the server used ClientHelloOuter, the client proceeds with the handshake,
authenticating for ESNIConfig.public_name as described in
{{auth-public-name}}. If authentication or the handshake fails, the client
MUST return a failure to the calling application. It MUST NOT use the retry
keys.

Otherwise, when the handshake completes successfully with the public name
authenticated, the client MUST abort the connection with an "esni_required"
alert. It then processes the "retry_keys" field from the server's
"encrypted_server_name" extension.

If one of the values contains a version supported by the client, it can regard
the ESNI keys as securely replaced by the server. It SHOULD retry the
handshake with a new transport connection, using that value to encrypt the
SNI. The value may only be applied to the retry connection. The client
MUST continue to use the previously-advertised keys for subsequent
connections. This avoids introducing pinning concerns or a tracking vector,
should a malicious server present client-specific retry keys to identify
clients.

If none of the values provided in "retry_keys" contains a supported version,
the client can regard ESNI as securely disabled by the server. As below, it
SHOULD then retry the handshake with a new transport connection and ESNI
disabled.

If the field contains any other value, the client MUST abort the connection
with an "illegal_parameter" alert.

If the server negotiates an earlier version of TLS, or if it does not
provide an "encrypted_server_name" extension in EncryptedExtensions, the
client proceeds with the handshake, authenticating for
ESNIConfig.public_name as described in {{auth-public-name}}. If an earlier
version was negotiated, the client MUST NOT enable the False Start optimization
{{RFC7918}} for this handshake. If authentication or the handshake fails, the
client MUST return a failure to the calling application. It MUST NOT treat this
as a secure signal to disable ESNI.

Otherwise, when the handshake completes successfully with the public name
authenticated, the client MUST abort the connection with an "esni_required"
alert. The client can then regard ESNI as securely disabled by the server. It
SHOULD retry the handshake with a new transport connection and ESNI disabled.

[[TODO: Key replacement is significantly less scary than saying that ESNI-naive
  servers bounce ESNI off. Is it worth defining a strict mode toggle in the ESNI
  keys, for a deployment to indicate it is ready for that? ]]

Clients SHOULD implement a limit on retries caused by "esni_retry_request" or
servers which do not acknowledge the "encrypted_server_name" extension. If the
client does not retry in either scenario, it MUST report an error to the
calling application.

#### Authenticating for the public name {#auth-public-name}

When the server cannot decrypt or does not process the "encrypted_server_name"
extension, it continues with the handshake using the cleartext "server_name"
extension instead (see {{server-behavior}}). Clients that offer ESNI then
authenticate the connection with the public name, as follows:

- If the server resumed a session or negotiated a session that did not use a
  certificate for authentication, the client MUST abort the connection with an
  "illegal_parameter" alert. This case is invalid because {{send-esni}} requires
  the client to only offer ESNI-established sessions, and {{server-behavior}}
  requires the server to decline ESNI-established sessions if it did not accept
  ESNI.

- The client MUST verify that the certificate is valid for ESNIConfig.public_name.
  If invalid, it MUST abort the connection with the appropriate alert.

- If the server requests a client certificate, the client MUST respond with an
  empty Certificate message, denoting no client certificate.

Note that authenticating a connection for the public name does not authenticate
it for the origin. The TLS implementation MUST NOT report such connections as
successful to the application. It additionally MUST ignore all session tickets
and session IDs presented by the server. These connections are only used to
trigger retries, as described in {{handle-server-response}}. This may be
implemented, for instance, by reporting a failed connection with a dedicated
error code.

### HelloRetryRequest

If the server sends a HelloRetryRequest in response to the ClientHello
and the client can send a second updated ClientHello per the rules in
{{RFC8446}}. At this point, the client does not know whether the
server processed ClientHelloOuter or ClientHelloInner, and MUST
regenerate both values to be acceptable. Note: if the inner and outer
ClientHellos use different groups for their key shares or differ in
some other way, then the HRR may actually be invalid for one or the
other ClientHello. In that case, the Client MUST continue the
handshake without changing the unaffected CH. Otherwise, the usual
rules for HRR processing apply.

[[OPEN ISSUE: This, along with trial decryption is
pretty gross. It would just be a lot easier if we were willing to
have the server indicate whether ESNI had been accepted or not.
Given that the server is supposed to only reject ESNI when it doesn't
know the key, and this is easy to probe for, can we just instead
have an extension to indicate what has happened.]]


## GREASE extensions {#grease-extensions}

If the client attempts to connect to a server and does not have an ESNIConfig
structure available for the server, it SHOULD send a GREASE
{{I-D.ietf-tls-grease}} "encrypted_client_hello" extension as follows:

- Select a supported cipher suite, named group, and padded_length
  value. The padded_length value SHOULD be 260 or a multiple of 16 less than
  260. Set the "suite" field  to the selected cipher suite. These selections
  SHOULD vary to exercise all supported configurations, but MAY be held constant
  for successive connections to the same server in the same session.

- Set the "key_share" field to a randomly-generated valid public key
  for the named group.

- Set the "record_digest" field to a randomly-generated string of hash_length
  bytes, where hash_length is the length of the hash function associated with
  the chosen cipher suite.

- Set the "encrypted_client_hello" field to a randomly-generated string of
  [TODO] bytes.

If the server sends an "encrypted_client_hello" extension, the client
MUST check the extension syntactically and abort the connection with a
"decode_error" alert if it is invalid.

Offering a GREASE extension is not considered offering an encrypted SNI for
purposes of requirements in {{client-behavior}}. In particular, the client MAY
offer to resume sessions established without ESNI.

# Client-Facing Server Behavior {#server-behavior}

Upon receiving an "encrypted_client_hello" extension, the client-facing
server MUST check that it is able to negotiate TLS 1.3 or greater. If not,
it MUST abort the connection with a "handshake_failure" alert.

The ClientEncryptedSNI value is said to match a known ESNIConfig if there exists
an ESNIConfig that can be used to successfully decrypt ClientEncryptedSNI.encrypted_sni.
This matching procedure should be done using one of the following two checks:

1. Compare ClientEncryptedSNI.record_digest against cryptographic hashes of known ESNIConfig
and choose the one that matches.
2. Use trial decryption of ClientEncryptedSNI.encrypted_sni with known ESNIConfig and choose
the one that succeeds.

Some uses of ESNI, such as local discovery mode, may omit the ClientEncryptedSNI.record_digest
since it can be used as a tracking vector. In such cases, trial decryption should be
used for matching ClientEncryptedSNI to known ESNIConfig. Unless specified by the application
using (D)TLS or externally configured on both sides, implementations MUST use the first method.

If the ClientEncryptedSNI value does not match any known ESNIConfig
structure, it MUST ignore the extension and proceed with the connection,
with the following added behavior:

- It MUST include the "encrypted_client_hello" extension with the
  "retry_keys" field set to one or more ESNIConfig structures with
  up-to-date keys. Servers MAY supply multiple ESNIConfig values of
  different versions. This allows a server to support multiple
  versions at once.

- The server MUST ignore all PSK identities in the ClientHello which correspond
  to ESNI PSKs. ESNI PSKs offered by the client are associated with the ESNI
  name. The server was unable to decrypt then ESNI name, so it should not resume
  them when using the cleartext SNI name. This restriction allows a client to
  reject resumptions in {{auth-public-name}}.

Note that an unrecognized ClientEncryptedSNI.record_digest value may be
a GREASE ESNI extension (see {{grease-extensions}}), so it is necessary
for servers to proceed with the connection and rely on the client to abort if
ESNI was required. In particular, the unrecognized value alone does not
indicate a misconfigured ESNI advertisement ({{misconfiguration}}). Instead,
servers can measure occurrences of the "esni_required" alert to detect this
case.

If the ClientEncryptedSNI value does match a known ESNIConfig, the server
performs the following checks:

- If the ClientEncryptedSNI.key_share group does not match one in the ESNIConfig.keys,
  it MUST abort the connection with an "illegal_parameter" alert.

Assuming these checks succeed, the server then computes K_sni
and decrypts the ClientHelloInner value. If decryption fails, the server
MUST abort the connection with a "decrypt_error" alert.

Once the ClientHelloInner has been decrypted, the server MUST
scan it for any "outer_extension" extensions and substitute their
values with the values in ClientHelloOuter. It MUST first verify that
the hash found in the extension matches the hash of the extension
to be interpolated in and if it does not, abort the connection
with a "decrypt_error" alert.

Upon determining the true SNI, the client-facing server then either
serves the connection directly (if in Shared Mode), in which case
it executes the steps in the following section, or forwards
the TLS connection to the backend server (if in Split Mode). In
the latter case, it does not make any changes to the TLS
messages, but just blindly forwards them.

If the server sends a NewSessionTicket message, the corresponding ESNI PSK MUST
be ignored by all other servers in the deployment when not negotiating ESNI,
including servers which do not implement this specification (in Split mode,
the server can detect this case by the presence of the "esni_info" extension).


# Compatibility Issues

Unlike most TLS extensions, placing the SNI value in an ESNI extension
is not interoperable with existing servers, which expect the value in
the existing cleartext extension. Thus server operators SHOULD ensure
servers understand a given set of ESNI keys before advertising them.
Additionally, servers SHOULD retain support for any
previously-advertised keys for the duration of their validity

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

The retry mechanism repairs inconsistencies, provided the server is
authoritative for the public name. If server and advertised keys mismatch,
the server will respond with esni_retry_requested. If the server does not understand the
"encrypted_server_name" extension at all, it will ignore it as required by {{RFC8446}};
Section 4.1.2. Provided the server can present a certificate valid for the public name,
the client can safely retry with updated settings, as described in {{handle-server-response}}.

Unless ESNI is disabled as a result of successfully establishing a connection to
the public name, the client MUST NOT fall back to cleartext SNI, as this allows
a network attacker to disclose the SNI.  It MAY attempt to use another server
from the DNS results, if one is provided.

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
Records are signed via a server private key, ESNI records have no
authenticity or provenance information. This means that any attacker
which can inject DNS responses or poison DNS caches, which is a common
scenario in client access networks, can supply clients with fake
ESNI records (so that the client encrypts SNI to them) or strip the
ESNI record from the response. However, in the face of an attacker that
controls DNS, no SNI encryption scheme can work because the attacker
can replace the IP address, thus blocking client connections, or
substituting a unique IP address which is 1:1 with the DNS name that
was looked up (modulo DNS wildcards). Thus, allowing the ESNI records in
the clear does not make the situation significantly worse.

Clearly, DNSSEC (if the client validates and hard fails) is a defense against
this form of attack, but DoH/DPRIVE are also defenses against DNS attacks
by attackers on the local network, which is a common case where SNI is
desired.
Moreover, as noted in the introduction, SNI encryption is less useful
without encryption of DNS queries in transit via DoH or DPRIVE mechanisms.

## Optional Record Digests and Trial Decryption

Supporting optional record digests and trial decryption opens oneself up to
DoS attacks. Specifically, an adversary may send malicious ClientHello messages, i.e.,
those which will not decrypt with any known ESNI key, in order to force
decryption. Servers that support this feature should, for example, implement
some form of rate limiting mechanism to limit the damage caused by such attacks.

## Encrypting other Extensions

ESNI protects only the SNI in transit. Other ClientHello extensions,
such as ALPN, might also reveal privacy-sensitive information to the
network. As such, it might be desirable to encrypt other extensions
alongside the SNI. However, the SNI extension is unique in that
non-TLS-terminating servers or load balancers may act on its contents.
Thus, using keys specifically for SNI encryption promotes key separation
between client-facing servers and endpoints party to TLS connections.
Moreover, the ESNI design described herein does not preclude a mechanism
for generic ClientHello extension encryption.

## Related Privacy Leaks

ESNI requires encrypted DNS to be an effective privacy protection mechanism.
However, verifying the server's identity from the Certificate message, particularly
when using the X509 CertificateType, may result in additional network traffic
that may reveal the server identity. Examples of this traffic may include requests
for revocation information, such as OCSP or CRL traffic, or requests for repository
information, such as authorityInformationAccess. It may also include
implementation-specific traffic for additional information sources as part of
verification.

Implementations SHOULD avoid leaking information that may identify the
server. Even when sent over an encrypted transport, such requests may result
in indirect exposure of the server's identity, such as indicating a specific CA
or service being used. To mitigate this risk, servers SHOULD deliver such
information in-band when possible, such as through the use of OCSP stapling,
and clients SHOULD take steps to minimize or protect such requests during
certificate validation.

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
by publishing different DNS records containing ESNIConfig values with different
keys using a short TTL.

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

Additionally, this specification allows for clients to send GREASE ESNI
extensions (see {{grease-extensions}}), which helps ensure the ecosystem
handles the values correctly.

### Forward secrecy

This design is not forward secret because the server's ESNI key is static.
However, the window of exposure is bound by the key lifetime. It is
RECOMMENDED that servers rotate keys frequently.

### Proper security context

This design permits servers operating in Split Mode to forward connections
directly to backend origin servers, thereby avoiding unnecessary MiTM attacks.

### Split server spoofing

Assuming ESNI records retrieved from DNS are authenticated, e.g., via DNSSEC or fetched
from a trusted Recursive Resolver, spoofing a server operating in Split Mode
is not possible. See {{cleartext-dns}} for more details regarding cleartext
DNS.

Authenticating the ESNIConfig structure naturally authenticates the
included public name. This also authenticates any retry signals
from the server because the client validates the server
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

## Update of the Resource Record (RR) TYPEs Registry

IANA is requested to create an entry, ESNI(0xff9f), in the existing
registry for Resource Record (RR) TYPEs (defined in {{!RFC6895}}) with
"Meaning" column value being set to "Encrypted SNI".

--- back


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
Matthew Prince, Nick Sullivan, Martin Thomson, and David Benjamin also provided
important ideas and contributions.
