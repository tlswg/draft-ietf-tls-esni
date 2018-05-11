---
title: Encrypted Server Name Indication for TLS 1.3
abbrev: TLS 1.3 SNI Encryption
docname: draft-rescorla-tls-esni-latest
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

normative:
  RFC2119:

informative:



--- abstract

This document defines a simple mechanism for encrypting the
Server Name Indication for TLS 1.3.

--- middle

# Introduction

Although TLS 1.3 {{!I-D.ietf-tls-tls13}} encrypts most of the
handshake, including the server certificate, there are several other
channels that allow an on-path attacker to determine domain name the 
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
({{?I-D.ietf-tls-sni-encryption}}; Section 2.4): if only hidden
services use SNI encryption, then SNI encryption is a signal that 
a client is going to a hidden server. For this reason,
the techniques in {{?I-D.ietf-tls-sni-encryption}} largely focus on
concealing the fact that SNI encryption is in use. Unfortunately,
the result often has undesirable performance consequences, incomplete
coverage, or both.

The design in this document takes a different approach: it assumes
that hidden servers will hide behind a provider (CDN, app server,
etc.) which is able to activate encrypted SNI (ESNI) for all of the domains
it hosts. Thus, the use of encrypted SNI does not indicate that the
client is attempting to reach a hidden server, but only that it is
going to a particular service provider, which the observer could
already tell from the IP address.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Overview

This document is designed to operate in one of two primary topologies
shown below, which we call "Shared Mode" and "Fronting Mode"

## Topologies

~~~~
                +--------------------+
                |                    |
                |   2001:DB8::1111   |
                |                    |
Client <----->  | hidden.example.org |
                |                    |
                | public.example.com |
                |                    |
                +--------------------+
                        Server
~~~~
{: #shared-mode title="Shared Mode Topology"}

In Shared Mode, the provider is the origin server for all the domains
whose DNS records point to it and clients form a TLS connection directly
to that provider, which has access to the plaintext of the connection.

~~~~
                +--------------------+       +--------------------+
                |                    |       |                    |
                |   2001:DB8::1111   |       |   2001:DB8::EEEE   |
Client <------------------------------------>|                    |
                | public.example.com |       | hidden.example.com |
                |                    |       |                    |
                +--------------------+       +--------------------+
                    Fronting Server               Hidden Server
~~~~
{: #fronting-mode title="Fronting Mode Topology"}

In Fronting Mode, the provider is *not* the origin server for hidden
domains. Rather the DNS records for hidden domains point to the provider,
but the provider's server just relays the connection back to the
hidden server, which is the true origin server. The provider does
not have access to the plaintext of the connection. In principle,
the provider might not be the origin for any domains, but as
a practical matter, it is probably the origin for a large set of
innocuous domains, but is also providing protection for some hidden
domains.


## SNI Encryption

The protocol designed in this document is quite straightforward.

First, the provider publishes a public key which is used for SNI encryption
for all the domains which it serves or fronts for. This document
defines a publication mechanism using DNS, but other mechanisms
are also possible. In particular, if some of the clients of
a hidden server are applications rather than Web browsers, those
applications might have the public key preconfigured.

When a client wants to form a TLS connection to any of the domains
served by an ESNI-supporting provider, it replaces the
"server_name" extension in the ClientHello with an "encrypted_server_name"
extension, which contains the true extension encrypted under the
provider's public key. The provider can then decrypt the extension
and either terminate the connection (in Shared Mode) or forward
it to the hidden server (in Fronting Mode).

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
        opaque label<0..2^8-1>;
        KeyShareEntry share;
    } ESNIKeyShare;

    struct {
        ESNIKeyShareEntry keys<4..2^16-1>;
        CipherSuite cipher_suites<2..2^16-2>;
    } ESNIKeys;
~~~~

label
: An opaque label to use for a given key.

share
: An (EC)DH key share (attached to the label)

keys
: The list of keys which can be used by the client to encrypt the SNI.
{:br}

The semantics of this structure are simple: any of the listed keys may
be used to encrypt the SNI for the associated domain name.
The cipher suite list is orthogonal to the
list of keys, so each key may be used with any cipher suite.

This structure is placed in the RRData section of a TXT record as 
encoded above. The Resource Record TTL determines the lifetime of
the published ESNI keys. Clients MUST NOT use ESNI keys beyond 
their recommended lifetime. 

# The "encrypted_server_name" extension {#esni-extension}

The encrypted SNI is carried in an "encrypted_server_name"
extension, which contains an EncryptedSNI structure:

~~~~
   struct {
       opaque label<0..2^8-1>;
       opaque nonce[16];
       CipherSuite suite;
       opaque encrypted_sni<0..2^16-1>;
   } EncryptedSNI;
~~~~

label
: The label associated with the SNI encryption key.

nonce
: A cryptographically random 128-bit nonce

suite
: The cipher suite used to encrypt the SNI.

encrypted_sni
: The original ServerNameList from the "server_name" extension,
  AEAD-encrypted using cipher suite "suite" and with the key
  generated as described below.
{:br}


## Client Behavior

In order to send an encrypted SNI, the client MUST first select one of
the server ESNIKeyShare values and generate an (EC)DHE share in the
matching group. This share is then used for the client's "key_share"
extension and will be used both to derive both the SNI encryption
key the (EC)DHE shared secret which is used in the TLS key schedule.
This has two important implications:

- The client MUST only provide one KeyShareEntry

- The server is committing to support every group in the
  ESNIKeys list (see below for server behavior).

The SNI encryption key is computed from the DH shared secret Z as
follows:

~~~~
   Z_extracted = HKDF-Extract(EncryptedSNI.nonce, Z)
   K_sni = HKDF-Expand-Label(Z_extracted, "encrypted-sni", ClientHello.Random, L)

   Where L is the key length associated with the cipher suite.
~~~~

The EncryptedSNI.encrypted_sni value is then computed by:

~~~~
    encrypted_sni = AEAD-Encrypt(K_sni, 0, "", ServerNameList)
~~~~

[[OPEN ISSUE: This is a strawman construction. We do want a
nonce to avoid situations where the server somehow reuses
a key, but exactly how we mix it in is TBD. Maybe in both
places?]]

This value is placed in an "encrypted_server_name" extension.

The client MAY either omit the "server_name" extension or provide
an innocuous dummy one. Similarly, the client MAY send an innocuous
EncryptedSNI extension if it has no ESNI to send.

## Fronting Server Behavior

Upon receiving an "encrypted_server_name" extension, the server
MUST first perform the following checks:

- If it is unable to negotiate TLS 1.3 or greater, it MUST
  abort the connection with a "handshake_failure" alert.

- If the EncryptedSNI.label value does not correspond to any known
  SNI encryption key, it MUST ignore the "encrypted_server_name"
  extension and continue with the handshake. This may involve
  using the "server_name" field if one is present. This has
  two benefits: (1) allowing clients to signal presence of ESNI
  and SNI, even if only one of them is legitimate, and (2) allowing
  servers to gracefully handle key rotation breaking clients in
  possession of an ESNI key.

- If more than one KeyShareEntry has been provided, or if that share's
  group does not match that for the SNI encryption key, it MUST abort
  the connection with an "illegal_parameter" alert.

Assuming that these checks succeed, the server then computes K_sni
and decrypts the ServerName value. If decryption fails, the server
MUST abort the connection with a "decrypt_error" alert. If decryption
succeeds, the server then uses the result as if it were the
"server_name" extension. Any actual "server_name" extension is
ignored.

Upon determining the true SNI, the fronting server then either
serves the connection directly (if in Shared Mode), in which case
it executes the steps in the following section, or forwards
the TLS connection to the hidden server (if in Fronting Mode).


## Hidden Server Behavior

The Hidden Server ignores both the "encrypted_server_name" and the
"server_name" (if any) and completes the handshake as usual. If in
Shared Mode, the server will still know the true SNI, and can use it
for certificate selection. In Fronting Mode, it may not know the true
SNI and so will generally be configured to use a single certificate


# Compatibility Issues

In general, this mechanism is designed only to be used with
servers which have opted in, thus minimizing compatibility
issues. However, there are two scenarios where that does not
apply, as detailed below.

## Misconfiguration

If DNS is misconfigured so that a client receives ESNI keys for a
server which is not prepared to receive ESNI, then the server will
ignore the "encrypted_server_name" extension, as required by
{{I-D.ietf-tls-tls13}}; Section 4.1.2.  If the servers does not
require SNI, it will complete the handshake with its default
certificate. Most likely, this will cause a certificate name
mismatch and thus handshake failure. Clients SHOULD not fall
back to cleartext SNI, because that allows a network attacker
to disclose the SNI. They MAY attempt to use another server
from the DNS results, if one is provided.


## Middleboxes

A more serious problem is MITM proxies which do not support this
extension. {{I-D.ietf-tls-tls13}}; Section 9.3 requires that
such proxies remove any extensions they do not understand,
which will either






# Security Considerations

## Why is cleartext DNS OK?

## Comparison Against Criteria

## Obvious Attacks


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

This document draws extensively from ideas in {{?I-D.kazuho-protected-sni}}, but
is a much more limited mechanism because it depends on the DNS for the
protection of the ESNI key. Richard Barnes, Christian Huitema, Patrick McManus,
Matthew Prince, Nick Sullivan, Martin Thomson, and Chris Wood also provided
important ideas.


