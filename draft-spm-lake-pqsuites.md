---
v: 3

title: Post-Quantum Cipher Suites for EDHOC
abbrev: PQ-suites for EDHOC
docname: draft-spm-lake-pqsuites-latest
category: std
submissiontype: IETF

ipr: trust200902
area: Security
workgroup: LAKE Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

coding: utf-8

author:
-
    ins: G. Selander
    name: Göran Selander
    org: Ericsson
    email: goran.selander@ericsson.com
-
    ins: J. Preuß Mattsson
    name: John Preuß Mattsson
    org: Ericsson
    email: john.mattsson@ericsson.com

normative:
  RFC2119:
  RFC9528:

informative:
  I-D.ietf-lake-edhoc-psk:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

The lightweight authenticated key exchange Ephemeral Diffie-Hellman over COSE (EDHOC) may be used with quantum safe algorithms, for example the ML-DSA signature algorithm. To take full advantage of post-quantum security, new cipher suites are needed. This document describes how EDHOC can be used in the post-quantum setting and specifies new cipher suites.

--- middle


# Introduction

Ephemeral Diffie-Hellman over COSE (EDHOC) {{RFC9528}} allows the specification of different authentication methods. Currently there are four public-key based algorithms (0, 1, 2, 3), and one symmetric-key based authentication method is being proposed {{I-D.ietf-lake-edhoc-psk}} here called "the PSK method".

Method 0, when both Initiator and Responder authenticate using digital signatures, can be directly applied with a post-quantum signature algorithm such as the Module-Lattice-Based Digital Signature Standard (ML-DSA) [FIPS204]. The PSK method is also applicable in the post-quantum setting.

Methods 1-3 are based on the static Diffie-Hellman keys, for which there are currently no post-quantum substitutes. Alternatively, new EDHOC methods based on a Key-Encapsulation Method (KEM) can be specified.

Method 0 with a post-quantum signature or the PSK method, when deployed with ephemeral Elliptic Curve Diffie-Hellman keys, does not provide post-quantum perfect forward secrecy and identity protection. Instead, a quantum safe KEM method such as the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) [FIPS203] can be used. For this reason, new cipher suites needs to be defined, see {{suites-registry}}.

## Terminology # {#terminology}

{::boilerplate bcp14}

Readers are expected to be familiar with EDHOC {{RFC9528}}.

# Security Considerations

TBD

# Privacy Considerations

TBD

# IANA Considerations

## EDHOC Cipher Suites Registry {#suites-registry}


IANA is requested to register the following entries in the EDHOC Cipher Suites Registry:

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD1
Array: 30, -45, 16, TBD3, -48, 10, -16
Description: AES-CCM-16-128-128, SHAKE‑256, 16, ML-KEM-512, ML-DSA-44,
AES-CCM-16-64-128, SHA-256
Reference: SELF
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD2
Array: 3, -45, 16, TBD3, -48, 30, -16
Description: A256GCM, SHAKE-256, 16, ML-KEM-512, ML-DSA-44,
A256GCM, SHA-256
Reference: SELF
~~~~~~~~~~~~~~~~~~~~~~~

--- back


# Acknowledgments # {#acknowledgment}
{: numbered="no"}

This work was supported partially by Vinnova - the Swedish Agency for Innovation Systems - through the EUREKA CELTIC-NEXT project CYPRESS.
