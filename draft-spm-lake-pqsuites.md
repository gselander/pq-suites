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
  I-D.sfluhrer-cfrg-ml-kem-security-considerations:
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


--- abstract

The Lightweight Authenticated Key Exchange (LAKE) protocol, Ephemeral Diffie-Hellman over COSE (EDHOC), achieves post-quantum security by adding new cipher suites with quantum-resistant algorithms, such as ML-KEM for key exchange and ML-DSA for digital signatures. This document specifies how EDHOC operates in a post-quantum setting using both signature-based and PSK-based authentication methods, and defines corresponding cipher suites.

--- middle


# Introduction

The Lightweight Authenticated Key Exchange (LAKE) protocol, Ephemeral Diffie-Hellman over COSE (EDHOC) {{RFC9528}}, supports the use of multiple authentication methods and the negotiation of cipher suites based on COSE algorithms. Currently, four asymmetric authentication methods (0, 1, 2, and 3) are defined. In addition, a symmetric key-based authentication method is being developed, see {{I-D.ietf-lake-edhoc-psk}}.

The cipher suites defined in {{RFC9528}} rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, making them vulnerable in the event that a Cryptographically Relevant Quantum Computer (CRQC) is realized.

This document specifies how EDHOC can operate in a post-quantum setting using both signature-based and PSK-based authentication, and defines corresponding cipher suites.

## Terminology # {#terminology}

{::boilerplate bcp14}

Readers are expected to be familiar with EDHOC {{RFC9528}}.


# EDHOC with Quantum-Resistant Algorithms

Method 0 in {{RFC9528}}, which uses digital signatures for authentication by both the Initiator and Responder, and also the PSK method in {{I-D.ietf-lake-edhoc-psk}}, is straightforward to use with standardized post-quantum algorithms.

A quantum-resistant signature algorithm, such as ML-DSA {{I-D.ietf-cose-dilithium}}, is a drop-in replacement for classical signature algorithms such as ECDSA. For post-quantum secure key exchange, a quantum-resistant Key Encapsulation Mechanism (KEM), such as ML-KEM {{I-D.ietf-jose-pqc-kem}}, can be applied directly to EDHOC, as is detailed in {{KEM}}.

To enable post-quantum security in EDHOC it suffices to register new cipher suites using COSE registered algorithms, see {{suites-registry}}.  Additional post-quantum cipher suites may be specified.

Methods 1–3 in {{RFC9528}} use a Diffie-Hellman/Non-Interactive Key Exchange (NIKE) based API for authentication. As of this writing, no standardized post-quantum algorithms for these methods exist. An alternative path to post-quantum EDHOC, not pursued in this document, would be to define new authentication methods based on Key Encapsulation Mechanisms (KEMs).

## Using KEMs for EDHOC Key Exchange {#KEM}

Given a quantum-resistant KEM, such as ML-KEM-512, with encapsulation key ek, ciphertext c, and shared secret key K (using the notation of {{FIPS203}}). The Diffie-Hellman procedure in EDHOC is replaced by a KEM procedure as follows:

* The Initiator generates a new encapsulation / decapsulation key pair matching the selected cipher suite.

* The encapsulation key ek is transported in the G_X field in message_1.

* The Responder calculates (K,c) = Encaps(ek).

* The ciphertext c is transported in the G_Y field in message_2.

* The Initiator calculates the shared secret K = Decaps(c).

* G_XY is the shared secret key K.

The security requirements and security considerations of EDHOC and the KEM algorithm used apply. For example, the Initiator MUST generate a new encapsulation / decapsulation key pair for each EDHOC session.

Note that G_Y does not contain a public key when a KEM is used in this way.

Note also that this use of KEM applies both to standalone KEM and hybrid KEMs such as, e.g., X-wing {{I-D.connolly-cfrg-xwing-kem}}.

Conventions for using post-quantum KEMs within COSE are described in {{I-D.ietf-jose-pqc-kem}}. The shared secret key K corresponds to the initial shared secret SS' in that document.

Compared to elliptic curve algorithms such as ECDHE, ECDSA, and EdDSA, ML-KEM-512 and ML-DSA-44 introduce significantly higher overhead {{FIPS203}}{{FIPS204}}. In the future, more efficient post-quantum signature schemes such as FN-DSA and MAYO may be considered, but these are not standardized at the time of this document’s publication.

Cipher suites using ML-KEM-512 {{I-D.ietf-jose-pqc-kem}} for key exchange and ML-DSA-44 {{I-D.ietf-cose-dilithium}} for digital signatures are specified in {{suites-registry}}. As both ML-KEM {{FIPS203}} and ML-DSA {{FIPS204}} internally use SHAKE256, it is natural to also use SHAKE256 for EDHOC's key derivation.

# Security Considerations

The cipher suites defined in {{RFC9528}} rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, which would be broken by a Cryptographically Relevant Quantum Computer (CRQC). In contrast, the cipher suites specified in this document use the quantum-resistant algorithms ML-KEM for key exchange and ML-DSA for authentication. When used with Method 0 from {{RFC9528}}, where both the Initiator and Responder authenticate using digital signatures, or with the PSK method defined in {{I-D.ietf-lake-edhoc-psk}}, these cipher suites preserve the same security properties even in the presence of a quantum-capable adversary.

Security considerations of ML-KEM are discussed in {{I-D.sfluhrer-cfrg-ml-kem-security-considerations}}.

# Privacy Considerations

TBD

# IANA Considerations

## EDHOC Method Type Registry

IANA is requested to update the EDHOC Method Type registry with a column with heading "Requires DH/NIKE" indicating that the method requires Diffie-Hellman or Non-Interactive Key Exchange. Valid table entries in this column are "Yes" and "No".

For the existing Method Types, the following entries are inserted in the new "Requires DH/NIKE" column:

~~~~~~~~~~~~~~~~~~~~~~~
Value: 0, Requires DH/NIKE: No
Value: 1, Requires DH/NIKE: Yes
Value: 2, Requires DH/NIKE: Yes
Value: 3, Requires DH/NIKE: Yes
~~~~~~~~~~~~~~~~~~~~~~~

## EDHOC Cipher Suites Registry {#suites-registry}

IANA is requested to update the EDHOC Cipher Suites registry with a column with heading "Supports DH/NIKE" indicating that the cipher suite supports Diffie-Hellman or Non-Interactive Key Exchange. Valid table entries in this column are "Yes" and "No".

For the existing EDHOC Cipher Suites, 0-6, 24, 25, the entry "Yes" is inserted in the new "Supports DH/NIKE" column.

Furthermore, IANA is requested to register the following entries in the EDHOC Cipher Suites Registry:

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD1
Array: 30, -45, 16, TBD3, -48, 10, -16
Description: AES-CCM-16-128-128, SHAKE256, 16, MLKEM512, ML-DSA-44,
             AES-CCM-16-64-128, SHA-256
Supports DH/NIKE: No
Reference: [[This document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD2
Array: 3, -45, 16, TBD3, -48, 30, -16
Description: A256GCM, SHAKE256, 16, MLKEM512, ML-DSA-44,
             A256GCM, SHA-256
Supports DH/NIKE: No
Reference: [[This document]]
~~~~~~~~~~~~~~~~~~~~~~~

--- back


# Acknowledgments # {#acknowledgment}
{: numbered="no"}

This work was supported partially by Vinnova - the Swedish Agency for Innovation Systems - through the EUREKA CELTIC-NEXT project CYPRESS.
