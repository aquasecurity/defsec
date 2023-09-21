module github.com/aquasecurity/defsec

go 1.19

require (
	github.com/alecthomas/chroma v0.10.0
	github.com/google/uuid v1.3.0
	github.com/hashicorp/hcl/v2 v2.17.0
	github.com/liamg/iamgo v0.0.9
	github.com/liamg/memoryfs v1.4.3
	github.com/owenrumney/squealer v1.1.1
	github.com/stretchr/testify v1.8.4
	github.com/zclconf/go-cty v1.13.0
	golang.org/x/text v0.11.0
	golang.org/x/tools v0.8.0

)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20221026131551-cf6655e29de4 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.4.0 // indirect
	github.com/go-git/go-git/v5 v5.5.2 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/liamg/jfather v0.0.7 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/pjbgf/sha1cd v0.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.1.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// See https://github.com/moby/moby/issues/42939#issuecomment-1114255529
//replace github.com/docker/docker => github.com/docker/docker v20.10.24+incompatible

replace github.com/elgohr/go-localstack => github.com/aquasecurity/go-localstack v0.0.0-20220706080605-1ec0e9b8753c

replace oras.land/oras-go => oras.land/oras-go v1.2.4-0.20230801060855-932dd06d38af
