# libICP

[![Build 
Status](https://travis-ci.com/OpenICP-BR/libICP.svg?branch=master)](https://travis-ci.com/OpenICP-BR/libICP)
[![Code 
Coverage](https://codecov.io/gh/OpenICP-BR/libICP/branch/master/graph/badge.svg)](https://codecov.io/gh/OpenICP-BR/libICP)
[![GoDoc](https://godoc.org/github.com/OpenICP-BR/libICP?status.svg)](https://godoc.org/github.com/gjvnq/OpenICP-BR)
![Semantic Version](https://img.shields.io/badge/semantic%20version-0.1.0-blue.svg)

A golang library for CAdES (CMS Advanced Electronic Signatures) for the Brazilian Public Key Infrastructure (ICP-Brasil).

# Features

- [X] Verify X509 digital certificates.
  - [X] Validity check.
  - [X] Integrity/signature check.
  - [X] Download all CAs on request.
  - [X] Check CRLs.
  - [X] Auto download CRLs.
  - [ ] Auto download CAs when needed.
  - [ ] Support certificate extensions.
    - [X] Basic Constraints.
    - [X] Key Usage.
    - [X] Authority Key Identifier.
    - [X] Subject Key Identifier.
    - [X] Key Usage.
    - [ ] Certificate Policies.
    - [X] CRL Distribution Points.
    - [X] Fail when critical extensions are not supported.
- [ ] CMS Content type support.
  - [ ] protection content
  - [ ] ContentInfo
  - [ ] data
  - [ ] signed-data
  - [ ] enveloped-data
- [ ] Join multiple signatures files into a single signature file.¹
- [ ] Support for smartcard certificates.
- [ ] Support for usb certificates.
- [ ] Support creation of AD-RB (Digital Signatures with Basic Reference).
  - [ ] Add detached signature to unsigned file.
  - [ ] Add attached signature to unsigned file.
  - [ ] Add cosignature to already signed file.
  - [ ] Add countersignature to already signed file.
- [ ] Support verification of AD-RB (Digital Signatures with Basic Reference).
- [ ] Support creation of AD-RT (Digital Signatures with Time Reference).
- [ ] Support verification of AD-RT (Digital Signatures with Time Reference).
- [ ] Support creation of AD-RV (Digital Signatures with References for Validation).
- [ ] Support verification of AD-RV (Digital Signatures with References for Validation).
- [ ] Support creation of AD-RC (Digital Signatures with Complete References).
- [ ] Support verification of AD-RC (Digital Signatures with Complete References).
- [ ] Support creation of AD-RA (Digital Signatures with References for Archival).
- [ ] Support verification of AD-RA (Digital Signatures with References for Archival).

¹: This is intended to handle situations in which multiple people signed a document "in parallel". Ex: a company contract is sent to five people via email. Each of the recipients generates their own signature file and send them back to the company. The company can simply "merge" these signatures into a single signature file as long as they are all valid and about the same document.

# Limitations

  * Only idPbeWithSHAAnd3KeyTripleDES_CBC (1.2.840.113549.1.12.1.3) using SHA1 is supported for key encryption. (this will change in the future)
  * The PFX decoding is a total mess that should be rewritten at some point.

# C Wrapper

A C wrapper is available under the `c-wrapper` directory. See the man files for reference.

If you can't run `make docs`, look at the `.pod` file in `c-wrapper/docs/src`.

# License

[AGPL - Affero GNU Public License](https://www.gnu.org/licenses/agpl-3.0.en.html)
