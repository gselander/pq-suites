---
v: 3

title: Quantum-Resistant Cipher Suites for EDHOC
abbrev: EDHOC PQC
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
  I-D.ietf-cose-dilithium:
  I-D.ietf-jose-pqc-kem:

informative:
  I-D.ietf-lake-edhoc-psk:
  I-D.connolly-cfrg-xwing-kem:
  I-D.fluhrer-cfrg-ml-kem-security-considerations:
  FIPS203:
    target: https://doi.org/10.6028/NIST.FIPS.203
    title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    seriesinfo:
      "NIST": "FIPS 203"
    author:
    date: August 2024
  FIPS204:
    target: https://doi.org/10.6028/NIST.FIPS.204
    title: Module-Lattice-Based Digital Signature Standard
    seriesinfo:
      "NIST": "FIPS 204"
    author:
    date: August 2024

entity:
  SELF: "[RFC-XXXX]"

--- abstract

The Lightweight Authenticated Key Exchange (LAKE) protocol, Ephemeral Diffie-Hellman over COSE (EDHOC), can trivally achieve post-quantum security by extending the support for new cipher suites with quantum-resistant algorithms such as ML-KEM for key exchange and ML-DSA for digital signatures. This document specifies how EDHOC can operate in a post-quantum setting using both signature-based and PSK-based authentication methods, and defines the corresponding cipher suites.

--- middle


# Introduction

The Lightweight Authenticated Key Exchange (LAKE) protocol, Ephemeral Diffie-Hellman over COSE (EDHOC) {{RFC9528}}, supports the use of multiple authentication methods and the negotiation of cipher suites based on COSE algorithms. Currently, four asymmetric authentication methods (0, 1, 2, and 3) are defined. In addition, a symmetric key-based authentication method is being developed in {{I-D.ietf-lake-edhoc-psk}}.

The cipher suites defined in {{RFC9528}} rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, making them vulnerable in the event that a Cryptographically Relevant Quantum Computer (CRQC) is realized.

This document specifies how EDHOC can operate in a post-quantum setting using both signature-based and PSK-based authentication, and defines the corresponding cipher suites.

## Terminology # {#terminology}

{::boilerplate bcp14}

Readers are expected to be familiar with EDHOC {{RFC9528}}.


# EDHOC with Quantum-Resistant Algorithms

Method 0 in {{RFC9528}}, which uses digital signatures for authentication by both the Initiator and Responder, and also the PSK method in {{I-D.ietf-lake-edhoc-psk}}, can trivally be used with standardized post-quantum algorithms.

A quantum-resistant signature algorithm, such as ML-DSA {{I-D.ietf-cose-dilithium}}, is a drop-in replacement for classical signature algorithms such as ECDSA. For post-quantum secure key exchange, a quantum-resistant Key Encapsulation Mechanism (KEM), such as ML-KEM {{I-D.ietf-jose-pqc-kem}}, can be applied directly to EDHOC, as is detailed in {{KEM}}.

To enable post-quantum security in EDHOC only requires new cipher suites to be registered, see {{suites-registry}}.

Methods 1–3 in {{RFC9528}} use a Diffie-Hellman/Non-Interactive Key Exchange (NIKE) based API for authentication. As of this writing, no standardized post-quantum algorithms for these methods exist. An alternative path to post-quantum EDHOC, not pursued in this document, would be to define new authentication methods based on Key Encapsulation Mechanisms (KEMs).

## Using KEMs for EDHOC Key Exchange {#KEM}

Given a quantum-resistant KEM, such as ML-KEM-512, with encapsulation key ek, ciphertext c and shared secret key K (using the notation of {{FIPS203}}). EDHOC is applied as follows:

* The encapsulation key ek is transported in the G_X field.
* The ciphertext c is is transported in the G_Y field.
* G_XY is the shared secret key K.

Relevant security requirements and considerations apply, for example, the Initiator MUST generate a new encapsulation / decapsulation key pair matching the selected cipher suite. Conventions for using post-quantum KEMs within COSE are described in {{I-D.ietf-jose-pqc-kem}}.

Note that this use of KEM applies both to standalone KEM and hybrid KEMs such as, e.g., X-wing {{I-D.connolly-cfrg-xwing-kem}}.

Compared to elliptic curve algorithms such as ECDHE, ECDSA, and EdDSA, ML-KEM-512 and ML-DSA-44 introduce significantly higher overhead {{FIPS203}}{{FIPS204}}. In the future, more efficient post-quantum signature schemes such as FN-DSA and MAYO may be considered, but these are not standardized at the time of this document’s publication.

Cipher suites using ML-KEM-512 {{I-D.ietf-jose-pqc-kem}} for key exchange and ML-DSA-44 {{I-D.ietf-cose-dilithium}} for digital signatures are specified in {{suites-registry}}. As both ML-KEM {{FIPS203}} and ML-DSA {{FIPS204}} internally use SHAKE256, it is natural to also use SHAKE256 for EDHOC's key derivation. Further post-quantum cipher suites may be added in the future.

# Security Considerations

The cipher suites defined in {{RFC9528}} rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, which would be broken by a Cryptographically Relevant Quantum Computer (CRQC). In contrast, the cipher suites specified in this document use the quantum-resistant algorithms ML-KEM for key exchange and ML-DSA for authentication. When used with Method 0 from {{RFC9528}}, where both the Initiator and Responder authenticate using digital signatures, or with the PSK method defined in {{I-D.ietf-lake-edhoc-psk}}, these cipher suites preserve the same security properties even in the presence of a quantum-capable adversary.

Security considerations of ML-KEM are discussed in {{I-D.fluhrer-cfrg-ml-kem-security-considerations}}.

# Privacy Considerations

TBD

# IANA Considerations

## EDHOC Cipher Suites Registry {#suites-registry}

IANA is requested to register the following entries in the EDHOC Cipher Suites Registry:

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD1
Array: 30, -45, 16, TBD3, -48, 10, -16
Description: AES-CCM-16-128-128, SHAKE256, 16, MLKEM512, ML-DSA-44,
             AES-CCM-16-64-128, SHA-256
Reference: SELF
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD2
Array: 3, -45, 16, TBD3, -48, 30, -16
Description: A256GCM, SHAKE256, 16, MLKEM512, ML-DSA-44,
             A256GCM, SHA-256
Reference: SELF
~~~~~~~~~~~~~~~~~~~~~~~

--- back


# Acknowledgments # {#acknowledgment}
{: numbered="no"}

This work was supported partially by Vinnova - the Swedish Agency for Innovation Systems - through the EUREKA CELTIC-NEXT project CYPRESS.
