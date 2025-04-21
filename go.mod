// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

module cunicu.li/go-openpgp-card

go 1.22.2

require cunicu.li/go-iso7816 v0.8.6

require (
	github.com/davecgh/go-spew v1.1.1 // test-only
	github.com/stretchr/testify v1.10.0 // test-only
	gopkg.in/yaml.v3 v3.0.1 // indirect; test-only
)

require (
	github.com/ebfe/scard v0.0.0-20241214075232-7af069cabc25 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
)
