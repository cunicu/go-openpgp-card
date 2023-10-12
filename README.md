# go-openpgp-card: A Go Implementation of the OpenPGP Smart Card application

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-openpgp-card/test.yaml?style=flat-square)](https://github.com/cunicu/go-openpgp-card/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-openpgp-card?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-openpgp-card)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-openpgp-card/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/go-openpgp-card/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-openpgp-card/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-openpgp-card?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-openpgp-card.svg)](https://pkg.go.dev/github.com/cunicu/go-openpgp-card)

`go-openpgp-card` is a Go package providing an interface to the OpenPGP application on ISO Smart Card Operating Systems.
It implements the [Functional Specification of the OpenPGP application in Version v3.4.1](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf).

## Install

When build with `CGO_ENABLED`, go-openpgp-card requires the following external dependencies.

```bash
apt-get install \
    libpcsclite-dev
```

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-openpgp-card is licensed under the [Apache 2.0](./LICENSE) license.

- SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
- SPDX-License-Identifier: Apache-2.0