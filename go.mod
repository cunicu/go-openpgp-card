module cunicu.li/go-openpgp-card

go 1.21.0

require (
	cunicu.li/go-iso7816 v0.2.2
	github.com/davecgh/go-spew v1.1.1
	golang.org/x/crypto v0.12.0
)

require (
	github.com/stretchr/testify v1.8.4 // test-only
	gopkg.in/yaml.v3 v3.0.1 // indirect; test-only
)

require (
	github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
)

replace cunicu.li/go-iso7816 => ../go-iso7816
