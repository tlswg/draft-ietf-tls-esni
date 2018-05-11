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
channels that allow an on-path attacker to determine the the major
mechanism that allows an on-path attacker to determine the domain
name the client is trying to connect to.

* The client's DNS lookups.
* The server IP address, if the server is not doing domain-based
  virtual hosting.
* The Server Name Indication (SNI) {{!RFC6066}} in the ClientHello.

DoH {{?I-D.ietf-doh-dns-over-https}} and DPRIVE {{?RFC7858}} {{?RFC8094}}
allow the client to conceal its DNS lookups from network inspection,
and many TLS servers host multiple domains on the same IP address.
In such environments, SNI is the major direct method of determining
the server's identity (although indirect mechanisms such as traffic
analysis also exist).

The TLS WG has extensively studied the problem of protecting SNI, but
has been unable to develop a completely generic
solution. {{?I-D.ietf-tls-sni-encryption}} provides a description
of the problem space and some of the proposed techniques. One of the
most difficult problems is "Do not stick out"
({{?I-D.ietf-tls-sni-encryption}}; Section 2.4): if only hidden
services use SNI encryption, then the use of SNI encryption is a
signal that the client is going to a hidden server. For this reason,
the techniques in {{?I-D.ietf-tls-sni-encryption}} largely focus on
concealing the fact that SNI encryption is in use. Unfortunately,
the result often has undesirable performance consequences, incomplete
covervage or both.

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
structure.

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

[[OPEN ISSUE: Do we need more Expiration dates, IP address limitations, etc.]]

[[TODO: How to shove this in a TXT record]]


# The "encrypted_server_name" extension {#esni-extension}

# Compatibility Issues


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


