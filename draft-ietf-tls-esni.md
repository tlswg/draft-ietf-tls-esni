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

The protocol designed in this document is quite straightforward.

First, the provider publishes a public key which is used for SNI encryption
for all the domains for which it serves directly or indirectly (via Split Mode).
This document defines a publication mechanism using DNS, but other mechanisms
are also possible. In particular, if some of the clients of
a private server are applications rather than Web browsers, those
applications might have the public key preconfigured.

When a client wants to form a TLS connection to any of the domains
served by an ESNI-supporting provider, it replaces the
"server_name" extension in the ClientHello with an "encrypted_server_name"
extension, which contains the true extension encrypted under the
provider's public key. The provider can then decrypt the extension
and either terminate the connection (in Shared Mode) or forward
it to the backend server (in Split Mode).

# Publishing the SNI Encryption Key in the DNS {#publishing-key}

Publishing ESNI keys in DNS requires care to ensure correct behavior.
There are deployment environments in which a domain is served by multiple server
operators who do not manage the ESNI Keys. Because ESNIKeys and A/AAAA lookup
are independent, it is therefore possible to obtain an ESNIKeys record which does
not match the A/AAAA records. (That is, the host to which an A or AAAA record
refers is not in possession of the ESNI keys.) Naively using this record would
result in handshake failure, and possibly require fallback to plaintext SNI.
The design of the system must therefore allow clients to detect and recover
from this situation.

Servers operating in Split Mode SHOULD have DNS configured to return
the same A (or AAAA) record for all ESNI-enabled servers they service. This yields
an anonymity set of cardinality equal to the number of ESNI-enabled server domains
supported by a given client-facing server. Thus, even with SNI encryption,
an attacker which can enumerate the set of ESNI-enabled domains supported
by a client-facing server can guess the correct SNI with probability at least
1/K, where K is the size of this ESNI-enabled server anonymity set. This probability
may be increased via traffic analysis or other mechanisms.

The following sections describe a DNS record format that achieve these goals.

## Host Pointers

Encrypted SNI records, described in {{esni-record}}, point to the (set of) hosts which possess
the private ESNI key. These pointers include (1) a canonical name which, if resolved, MUST yield A
or AAAA records that possess the corresponding private key, and (2) a set of CIDR blocks,
each possibly of size 1, that match the IPv4 or IPv6 address of a host with the private key.

These "host pointers" are encoded using the following structure.

~~~~
    enum {
        address_v4,
        address_v6,
    } AddressType;

    struct {
        AddressType address_type;
        select (address_type) {
            case address_v4: {
                uint8 ipv4Length;
                opaque ipv4Address[4];
            }
            case address_v6: {
                uint8 ipv6Length;
                opaque ipv6Address[16];
            }
        }
    } Address;

    struct {
        HostName name;
        Address address_set<0..2^16-1>;
    } HostPointer;
~~~~

name
: The terminal name for which resolution must yield valid A or
AAAA records pointing to a host which holds the private ESNI key.

address_set
: An optional list of Address entries, each containing a single IPv4 or IPv6
CIDR block, possibly of length 1.

Use of this structure during the ESNI resolution algorithm is described in {{esni-resolution}}.

## Encrypted SNI Record {#esni-record}

SNI Encryption keys can be published using the following ESNIKeys structure.

~~~~
    // Copied from TLS 1.3
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;

    struct {
        uint16 version;
        uint8 checksum[4];
        KeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
        uint16 padded_length;
        uint64 not_before;
        uint64 not_after;
        HostPointer host_pointer;
        Extension extensions<0..2^16-1>;
    } ESNIKeys;
~~~~

version
: The version of the structure. For this specification, that value
SHALL be 0xff01. Clients MUST ignore any ESNIKeys structure with a
version they do not understand.
[[NOTE: This means that the RFC will presumably have a nonzero value.]]

checksum
: The first four (4) octets of the SHA-256 message digest {{RFC6234}}
of the ESNIKeys structure. For the purpose of computing the checksum, the
value of the "checksum" field MUST be set to zero.

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

host_pointer
: A HostPointer structure containing address information for the hosts
carrying the corresponding private ESNI key.

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

## Encrypted SNI DNS Resolution {#esni-resolution}

Clients obtain ESNI records by querying DNS for ESNI-enabled server domains.
In cases where the domain of the A or AAAA records being resolved do not match the
SNI Server Name, such as when {{!RFC7838}} is being used, the alternate domain should
be used for querying the ESNI TXT record.

Clients SHOULD initiate ESNI queries in parallel alongside normal A or AAAA queries.
The following algorithm describes a procedure by which clients can process ESNIKeys
responses as they arrive to produce addresses for ESNI-capable hosts.

~~~
1. If an ESNIKeys response arrives before an A or AAAA response, and the ESNIKeys
response contains a full address, clients should initiate TLS with ESNI to the
provided address(es).

2. If an A or AAAA response arrives before the ESNIKeys response, clients should
wait up to CD seconds before initiating TLS to either address. (Clients may begin
  TCP connections in this time. QUIC connections should wait.) If an ESNIKeys
  response does not arrive in this time, clients should initiate TLS without ESNI
  to the provided address(es).

3. If an ESNIKeys response arrives before this time, and if the address netmask
matches that in the corresponding A or AAAA response, then clients should initiate
TLS with ESNI to said address(es). (An ESNIKeys record with a full address has a
  full netmask, and therefore the match must be exact.) Clients may delay this
  check until both A and AAAA responses arrive, or if a Resolution Delay timeout
  occurs, according to {{RFC8305}}.

4. If the address netmask does not match the corresponding A or AAAA response,
and the A or AAAA response yielded a terminal CNAME that matches ESNIKeys.host_pointer.name,
then clients should initiate TLS using ESNI to the address(es) in the A or AAAA records.

5. If the address netmask does not match the corresponding A or AAAA response,
and neither the A or AAAA queries yielded a CNAME that matches ESNIKeys.host_pointer.name,
clients should resolve the address of ESNIKeys.host_pointer.name using an
address type that matches the A or AAAA response. Clients should initiate TLS
using ENSI to the resulting address(es) when A or AAAA resolution completes.

6. If the ESNIKeys.host_pointer address set is empty, clients should resolve the
address(es) of ESNIKeys.host_pointer.name and initiate TLS to the resulting address(es).

7. In all other cases, raise an error.
~~~

CD (Connection Delay) is a configurable parameter. The recommended value is 50 milliseconds,
as per the guidance in {{!RFC8305}}. This algorithm (probabilistically) converges towards
addresses of ESNI-capable domains. Clients who do not wish to spend a round trip to
resolve ESNIKeys host addresses may initiate TLS to the hosts specified in the A or AAAA
responses without ESNI. Similarly, clients that do not wish to implement ESNI support for
incomplete ESNIKeys addresses may skip all sets using them. ESNI-capable clients MUST support
ESNIKeys with full addresses.

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
   struct {
       uint8 nonce[16];
   } ServerEncryptedSNI;
~~~

nonce
: The contents of ClientESNIInner.nonce. (See {{client-behavior}}.)

## Client Behavior {#client-behavior}

In order to send an encrypted SNI, the client MUST first select one of
the server ESNIKeyShareEntry values and generate an (EC)DHE share in the
matching group. This share will then be sent to the server in the
"encrypted_sni" extension and used to derive the SNI encryption key. It does not affect the
(EC)DHE shared secret used in the TLS key schedule. It MUST also select
an appropriate cipher suite from the list of suites offered by the
server. If the client is unable to select an appropriate group or suite it SHOULD ignore that ESNIKeys value and MAY attempt to use another value provided by the server (recall that servers might provide multiple ESNIKeys in response to a ESNI TXT query).
The client MUST NOT send
encrypted SNI using groups or cipher suites not advertised by the server.

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

The client MAY either omit the "server_name" extension or provide
an innocuous dummy one (this is required for technical conformance
with {{!RFC7540}}; Section 9.2.)

If the server does not negotiate TLS 1.3 or above, then the client
MUST abort the connection with an "unsupported_version" alert.
If the server does not provide an "encrypted_server_name" extension
in EncryptedExtensions, the client MUST abort the connection with
an "illegal_parameter" alert. Moreover, it MUST check that
ClientESNIInner.nonce matches the value of the
"encrypted_server_name" extension provided by the server,
and otherwise abort the connection with an "illegal_parameter"
alert.

## Client-Facing Server Behavior

Upon receiving an "encrypted_server_name" extension, the client-facing
server MUST first perform the following checks:

- If it is unable to negotiate TLS 1.3 or greater, it MUST
  abort the connection with a "handshake_failure" alert.

- If the ClientEncryptedSNI.record_digest value does not match the cryptographic
  hash of any known ESNIKeys structure, it MUST abort the connection with
  an "illegal_parameter" alert. This is necessary to prevent downgrade attacks.
  [[OPEN ISSUE: We looked at ignoring the extension but concluded
  this was better.]]

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
include the "encrypted_server_name" extension in EncryptedExtensions,
and the value of this extension MUST match PaddedServerNameList.nonce.

## Split Mode Server Behavior {#backend-server-behavior}

In Split Mode, the backend server must know PaddedServerNameList.nonce
to echo it back in EncryptedExtensions and complete the handshake.
{{communicating-sni}} describes one mechanism for sending both
PaddedServerNameList.sni and ClientESNIInner.nonce to the backend
server. Thus, backend servers function the same as servers operating
in Shared Mode.

# Compatibility Issues

In general, this mechanism is designed only to be used with
servers which have opted in, thus minimizing compatibility
issues. However, there are two scenarios where that does not
apply, as detailed below.

## Misconfiguration

If DNS is misconfigured so that a client receives ESNI keys for a
server which is not prepared to receive ESNI, then the server will
ignore the "encrypted_server_name" extension, as required by
{{RFC8446}}; Section 4.1.2.  If the servers does not
require SNI, it will complete the handshake with its default
certificate. Most likely, this will cause a certificate name
mismatch and thus handshake failure. Clients SHOULD NOT fall
back to cleartext SNI, because that allows a network attacker
to disclose the SNI. They MAY attempt to use another server
from the DNS results, if one is provided.


## Middleboxes

A more serious problem is MITM proxies which do not support this
extension. {{RFC8446}}; Section 9.3 requires that
such proxies remove any extensions they do not understand.
This will have one of two results when connecting to the client-facing
server:

1. The handshake will fail if the client-facing server requires SNI.
2. The handshake will succeed with the client-facing server's default
   certificate.

A Web client client can securely detect case (2) because it will result
in a connection which has an invalid identity (most likely)
but which is signed by a certificate which does not chain
to a publicly known trust anchor. The client can detect this
case and disable ESNI while in that network configuration.

In order to enable this mechanism, client-facing servers SHOULD NOT
require SNI, but rather respond with some default certificate.

A non-conformant MITM proxy will forward the ESNI extension,
substituting its own KeyShare value, with the result that
the client-facing server will not be able to decrypt the SNI.
This causes a hard failure. Detecting this case is difficult,
but clients might opt to attempt captive portal detection
to see if they are in the presence of a MITM proxy, and if
so disable ESNI. Hopefully, the TLS 1.3 deployment experience
has cleaned out most such proxies.


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

IANA is requested to Create an entry, encrypted_server_name(0xffce),
in the existing registry for ExtensionType (defined in
{{!RFC8446}}), with "TLS 1.3" column values being set to
"CH, EE", and "Recommended" column being set to "Yes".

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


