// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

module cunicu.li/go-openpgp-card

go 1.21.3

require cunicu.li/go-iso7816 v0.3.0

require (
	github.com/davecgh/go-spew v1.1.1 // test-only
	github.com/stretchr/testify v1.8.4 // test-only
	gopkg.in/yaml.v3 v3.0.1 // indirect; test-only
)

require (
	github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.1 // indirect
)
