# libICP

[![Build Status](https://travis-ci.com/gjvnq/libICP.svg?branch=master)](https://travis-ci.com/gjvnq/libICP)
[![Code Coverage](https://codecov.io/gh/gjvnq/libICP/branch/master/graph/badge.svg)](https://codecov.io/gh/gjvnq/libICP)
[![GoDoc](https://godoc.org/github.com/gjvnq/libICP?status.svg)](https://godoc.org/github.com/gjvnq/libICP)

A golang library for CAdES (CMS Advanced Electronic Signatures) for the Brazilian Public Key Infrastructure (ICP-Brasil).

# Features

- [X] Verify X509 digital certificates.
  - [X] Validity check.
  - [X] Integrity/signature check.
  - [X] Download all CAs on request.
  - [ ] Check CRLs.
  - [ ] Auto download CRLs.
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

¹: This is intended to handle situations in which multiple people signed a document "in parallel". Ex: a company contract is sent to five people via email. Each of the recipients generature their own signature file and send them back to the company. The company can simply "merge" these signatures into a single signature file as long as they are all valid and about the same document.

# License

[AGPL - Affero GNU Public License](https://www.gnu.org/licenses/agpl-3.0.en.html)