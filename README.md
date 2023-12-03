<!--
SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
SPDX-License-Identifier: Apache-2.0
-->

# go-openpgp-card: A Go Implementation of the OpenPGP Smart Card application

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-openpgp-card/build.yaml?style=flat-square)](https://github.com/cunicu/go-openpgp-card/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-openpgp-card?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-openpgp-card)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-openpgp-card/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/go-openpgp-card/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-openpgp-card/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-openpgp-card?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-openpgp-card.svg)](https://pkg.go.dev/github.com/cunicu/go-openpgp-card)

`go-openpgp-card` is a Go package providing an interface to the OpenPGP application on ISO Smart Card Operating Systems.

## Features

`go-openpgp-card` implements the [Functional Specification of the OpenPGP application in Version v3.4.1](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf).

- Supported commands:
  - [x] 7.2.1 `SELECT`
  - [x] 7.2.2 `VERIFY`
  - [x] 7.2.3 `CHANGE REFERENCE DATA`
  - [x] 7.2.4 `RESET RETRY COUNTER`
  - [x] 7.2.5 `SELECT DATA`
  - [x] 7.2.6 `GET DATA`
    - [x] Application related
    - [x] Security Support Template
    - [x] Private data
    - [x] Cardholder related
    - [x] Password status
    - [x] Login data
    - [x] Public key URL
    - [x] Cardholder certificates
    - [ ] User interaction flag
  - [x] 7.2.7 `GET NEXT DATA`
  - [x] 7.2.8 `PUT DATA`
    - [x] Resetting Code
    - [x] Name
    - [x] Language
    - [x] Sex
    - [x] Public Key URL
    - [x] Login data
    - [x] Private data
    - [x] User interaction flag
    - [x] Password status
    - [ ] Key Import
      - [x] AES
      - [x] RSA
      - [x] ECDSA
      - [x] EdDSA
  - [x] 7.2.9 `GET RESPONSE`
  - [ ] 7.2.10 `PSO: COMPUTE DIGITAL SIGNATURE`
    - [ ] RSA
    - [x] ECDSA
    - [x] EdDSA
  - [ ] 7.2.11 `PSO: DECIPHER`
    - [x] AES
    - [ ] RSA
    - [x] ECDH
    - [x] EdDSA
  - [ ] 7.2.12 `PSO: ENCIPHER`
    - [x] AES
  - [ ] 7.2.13 `INTERNAL AUTHENTICATE`
    - [ ] RSA
    - [ ] ECDSA
    - [ ] EdDSA
  - [x] 7.2.14 `GENERATE ASYMMETRIC KEY PAIR`
    - [x] RSA
    - [x] Elliptic Curves
  - [x] 7.2.15 `GET CHALLENGE`
  - [x] 7.2.16 `TERMINATE DF`
  - [x] 7.2.17 `ACTIVATE FILE`
  - [x] 7.2.18 `MANAGE SECURITY ENVIRONMENT`

- [x] Key Derivation Function (KDF) for `VERIFY`
- [ ] PIN Handler / Callback

### YubiKey extensions

- [x] Set PIN Retry counters
- [ ] Attestation

## Tested implementations

- Yubikey
  - FW version 5.4.3

## Install

go-openpgp-card needs to be build with `CGO_ENABLED=1` and requires the following external dependencies:

```bash
apt-get install \
    libpcsclite-dev
```

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-openpgp-card is licensed under the [Apache 2.0](./LICENSE) license.
