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

This structure is placed in the RRData section of a TXT record as 
encoded above. The Resource Record TTL determines the lifetime of
the published ESNI keys. Clients MUST NOT use ESNI keys beyond 
their recommended lifetime. 

# The "encrypted_server_name" extension {#esni-extension}

ESNIs are carried in an extension similar to the SNI, with the 
following extension type:

~~~
enum {
    ...
    encrypted_server_name(TBD),
    (65535)
} ExtensionType;
~~~

The contents of this extension are as follows:
~~~
struct {
        opaque label<0..2^8-1>;
        opaque esni<1..2^16-1>;
} ESNI-Extension;
~~~

# Client SNI Encryption

Let X be the client's ephemeral key share in a group that matches one
of the NamedGroup entries in ESNIKeys. Let Y be the corresponding key
share (key_exchange) value in ESNIKeys. To encrypt the SNI, clients first
compute an (EC)DH operation between X and Y, yielding a secret S.
A shared secret esni_key is then derived from S as follows:

~~~ 
esni_key = HKDF-Extract(0, S)
~~~

This key is then used to encrypt the SNI, using all information in the
Client Hello preceding any PSK binders that may be present as Associated Data (additional_data). 
Thus, the ESNI extension MUST be last in the extension list before the 
PreSharedKeyExtension, if present. Following 4.2.11.2 of {{!I-D.ietf-tls-tls13}},
the contents of this preceding data may be computed as follows:

~~~
 TruncateToESNI(ClientHello)
~~~

Where TruncateToESNI() removes all information from ClientHello1 up to the
ESNI extension. Encryption of plaintext value `sni`, e.g., example.com, is then 
performed as follows:

~~~
ESNI = AEAD-Encrypt(esni_key, 0, TruncateToESNI(ClientHello), sni)
~~~

Clients MUST NOT re-use esni_key more than once, as this would lead to
encryption with nonce re-use. Nonce re-use across clients would only occur
if two clients happened to generate the same key share (X).

# Server SNI Decryption

When a server -- fronting or shared -- receives a ClientHello with an ESNI 
extension, it does the following:

1. Lookup the secret key corresponding to the key in the label.
2. Perform the same (EC)DH operation to derive S, and from that, derive esni_key.
3. Decrypt the `esni` value in the ESNI-Extension using esni_key.

The server may then use the plaintext SNI to route the ClientHello to the correct
service or hidden server.

If Step (1) fails because (a) the server rotated its ESNI keys or (b) a matching
label does not exist, the server SHOULD proceed with the connection as if no 
ESNI-Extension was present. 

# Compatibility Issues

TODO

# Security Considerations

TODO Security


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


