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
etc.) which is able to activate encrypted SNI for all of the domains
it hosts. Thus, the use of encrypted SNI does not indicate that the
client is attempting to reach a hidden server, but only that it is
going to a particular service provider, which the observer could
already tell from the IP address.






# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
