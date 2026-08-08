---
v: 3

title: Quantum-Resistant Cipher Suites for LAKE
abbrev: LAKE PQC
docname: draft-spm-lake-pqsuites-latest
category: std
submissiontype: IETF

v3xml2rfc:
  silence:
  - Found SVG with width or height specified

ipr: trust200902
area: Security
workgroup: LAKE Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

coding: utf-8


venue:
  group: "Lightweight Authenticated Key Exchange"
  type: "Working Group"
  mail: "lake@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/lake/"
  github: "gselander/pq-suites"

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

The Lightweight Authenticated Key Exchange (LAKE) protocol, also known as Ephemeral Diffie-Hellman over COSE (EDHOC), achieves post-quantum security by adding new cipher suites with quantum-resistant algorithms, such as ML-DSA for digital signatures and ML-KEM for key exchange. This document specifies how the LAKE protocol operates in a post-quantum setting using both signature-based and PSK-based authentication methods, and defines corresponding cipher suites.

--- middle


# Introduction

The Lightweight Authenticated Key Exchange (LAKE) protocol defined in {{RFC9528}}, also known as Ephemeral Diffie-Hellman over COSE (EDHOC), supports the use of multiple authentication methods and the negotiation of cipher suites based on COSE algorithms. Currently, four asymmetric authentication methods (0, 1, 2, and 3) are defined. In addition, a symmetric key-based authentication method is being developed, see {{I-D.ietf-lake-edhoc-psk}}.

Currently defined cipher suites rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, making them vulnerable in the event that a Cryptographically Relevant Quantum Computer (CRQC) is constructed.

This document specifies how the LAKE protocol can operate in a post-quantum setting using both signature-based and PSK-based authentication, and defines corresponding cipher suites. With this modification the protocol is no longer dependent on Diffie-Hellman which makes EDHOC a misnomer and we henceforth use the name LAKE for the protocol.

## Terminology # {#terminology}

{::boilerplate bcp14}

Readers are expected to be familiar with {{RFC9528}}. To avoid misunderstanding of the capabilities of the protocol, the name EDHOC is replaced by LAKE. To avoid misunderstanding with terminology from {{RFC9528}}, the prefix EDHOC is retained when needed, for example in the IANA registries.


# LAKE with Quantum-Resistant Algorithms

Method 0 in {{RFC9528}}, which uses digital signatures for authentication by both the Initiator and Responder, and also the PSK method in {{I-D.ietf-lake-edhoc-psk}}, is straightforward to use with standardized post-quantum algorithms.

A quantum-resistant signature algorithm, such as ML-DSA {{I-D.ietf-cose-dilithium}}, is a drop-in replacement for classical signature algorithms such as ECDSA. For post-quantum secure key exchange, a quantum-resistant Key Encapsulation Mechanism (KEM), such as ML-KEM {{I-D.ietf-jose-pqc-kem}}, can be applied directly to the LAKE protocol, as is detailed in {{KEM}}.

To enable post-quantum security support for LAKE it suffices to register new cipher suites using COSE registered algorithms. Cipher suites using ML-KEM-512 {{I-D.ietf-jose-pqc-kem}} for key exchange and ML-DSA-44 {{I-D.ietf-cose-dilithium}} for digital signatures are specified in {{suites-registry}}. As both ML-KEM {{FIPS203}} and ML-DSA {{FIPS204}} internally use SHAKE256, it was natural to also use SHAKE256 for key derivation. Additional post-quantum cipher suites may be specified.

Methods 1–3 in {{RFC9528}} use a Diffie-Hellman/Non-Interactive Key Exchange (NIKE) based API for authentication. As of this writing, no standardized post-quantum algorithms for these methods exist. To highlight which methods that require DH/NIKE a column is added to the EDHOC Method Type registry, see {{method-update}}. To highlight matching cipher suites a corresponding column indicating support for DH/NIKE is added, see {{suites-registry}}.

An alternative path to post-quantum support for the LAKE protocol, not pursued in this document, is to define new authentication methods based on Key Encapsulation Mechanisms (KEMs).

Compared to elliptic curve algorithms such as ECDHE, ECDSA, and EdDSA, ML-KEM-512 and ML-DSA-44 introduce significantly higher overhead {{FIPS203}}{{FIPS204}}. More efficient post-quantum signature schemes are being standardized, such as FN-DSA.

# Using KEMs in the Key Exchange {#KEM}

Given a quantum-resistant KEM, such as ML-KEM-512, with encapsulation key ek, ciphertext c, and shared secret key K (using the notation of {{FIPS203}}). The Diffie-Hellman procedure in the key exchange is replaced by a KEM procedure as follows:

* The Initiator generates a new encapsulation / decapsulation key pair matching the selected cipher suite.

* The encapsulation key ek is transported in the G_X field in message_1.

* The Responder calculates (K,c) = Encaps(ek).

* The ciphertext c is transported in the G_Y field in message_2.

* The Initiator calculates the shared secret K = Decaps(c).

* G_XY is the shared secret key K.

The security requirements and security considerations of {{RFC9528}} and the KEM algorithm used apply. For example, the Initiator MUST generate a new encapsulation / decapsulation key pair for LAKE session.

Note that G_Y does not contain a public key when a KEM is used in this way. The definition of LAKE message_2 in {{Section 5.3.1 of RFC9528}} remains the same:

~~~~~~~~~~~ CDDL
message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~

and G_Y_CIPHERTEXT_2 remains the concatenation of G_Y and CIPHERTEXT_2, the latter is defined in {{Section 5.3.2 of RFC9528}}. But now G_Y is a KEM ciphertext.

Just as with the ephemeral key G_Y, the length of KEM ciphertext G_Y is known from the corresponding algorithm in the selected cipher suite, see {{fig-ct-length}}. Hence the Initator can separate out the concatenated ciphertexts and decapsulate and decrypt, respectively.

~~~~~~~~~~~
+-------------+------------------------------+
|     KEM     | Length of ciphertext (bytes) |
+=============+==============================+
| ML‑KEM‑512  |                          768 |
| ML‑KEM‑768  |                         1088 |
| ML‑KEM‑1024 |                         1568 |
+-------------+------------------------------+
~~~~~~~~~~~
{: #fig-ct-length title="Length of ML-KEM Ciphertext."}

Note also that this use of KEM applies both to standalone KEM and hybrid KEMs such as, e.g., X-wing {{I-D.connolly-cfrg-xwing-kem}}.

Conventions for using post-quantum KEMs within COSE are described in {{I-D.ietf-jose-pqc-kem}}. The shared secret key K corresponds to the initial shared secret SS' in that document.

# Security Considerations

The cipher suites defined in {{RFC9528}} rely on Elliptic Curve Cryptography (ECC) for key exchange and authentication, which would be broken by a Cryptographically Relevant Quantum Computer (CRQC). In contrast, the cipher suites specified in this document use the quantum-resistant algorithms ML-KEM for key exchange and ML-DSA for authentication. When used with Method 0 from {{RFC9528}}, where both the Initiator and Responder authenticate using digital signatures, or with the PSK method defined in {{I-D.ietf-lake-edhoc-psk}}, these cipher suites preserve the same security properties even in the presence of a quantum-capable adversary.

Security considerations of ML-KEM are discussed in {{I-D.sfluhrer-cfrg-ml-kem-security-considerations}}.

# Privacy Considerations

TBD

# IANA Considerations

## EDHOC Method Type Registry {#method-update}

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

For the existing cipher suites 0-6, 24, 25, the entry "Yes" is inserted in the new "Supports DH/NIKE" column.

Furthermore, IANA is requested to register the following entries in the EDHOC Cipher Suites Registry:

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD1
Array: 30, -45, 16, TBD10, -48, 10, -16
Description: AES-CCM-16-128-128, SHAKE256, 16, MLKEM512, ML-DSA-44,
             AES-CCM-16-64-128, SHA-256
Supports DH/NIKE: No
Reference: [[This document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD2
Array: 3, -45, 16, TBD10, -48, 3, -16
Description: A256GCM, SHAKE256, 16, MLKEM512, ML-DSA-44,
             A256GCM, SHA-256
Supports DH/NIKE: No
Reference: [[This document]]
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Value: TBD3
Array: 3, -43, 16, TBD12, -48, 3, -43
Description: A256GCM, SHA-384, 16, MLKEM1024, ML-DSA-85,
             A256GCM, SHA-384
Supports DH/NIKE: No
Reference: [[This document]]
~~~~~~~~~~~~~~~~~~~~~~~

Cipher suite TBD3 is intended for for high security applications such as government use and financial applications. This cipher suites consists of algorithms from the Commercial National Security Algorithm (CNSA) 2.0 suite [CNSA2].

--- back


# Acknowledgments # {#acknowledgment}
{: numbered="no"}

This work was supported partially by Vinnova - the Swedish Agency for Innovation Systems - through the EUREKA CELTIC-NEXT project CYPRESS.
