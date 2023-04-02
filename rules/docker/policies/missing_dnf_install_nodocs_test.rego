package builtin.dockerfile.DS028

test_dnf_denied {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "run",
			"Value": ["set -uex &&     dnf install -vy docker-ce &&     dnf clean all"],
		},
		{
			"Cmd": "healthcheck",
			"Value": [
				"CMD",
				"curl --fail http://localhost:3000 || exit 1",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'--nodocs' is missing for dnf package installation: set -uex &&     dnf install -vy docker-ce &&     dnf clean all"
}

test_dnf_allowed {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf install --nodocs -vy docker-ce &&     dnf clean all"],
		},
		{
			"Cmd": "healthcheck",
			"Value": [
				"CMD",
				"curl --fail http://localhost:3000 || exit 1",
			],
		},
	]}]}

	count(r) == 0
}

# # write the same with microdnf tests

# test_missing_with_install_flags {
# 	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
# 		{
# 			"Cmd": "from",
# 			"Value": ["alpine:3.5"],
# 		},
# 		{
# 			"Cmd": "run",
# 			"Value": ["dnf install -vy docker-ce && dnf clean all"],
# 		},
# 		{
# 			"Cmd": "healthcheck",
# 			"Value": [
# 				"CMD",
# 				"curl --fail http://localhost:3000 || exit 1",
# 			],
# 		},
# 	]}]}

# 	count(r) == 1
# 	r[_].msg == "'--nodocs missing': dnf install -vy docker-ce && dnf clean all"
# }

# test_reinstall_missing_denied {
# 	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
# 		{
# 			"Cmd": "from",
# 			"Value": ["alpine:3.5"],
# 		},
# 		{
# 			"Cmd": "run",
# 			"Value": ["dnf reinstall bash zsh && dnf clean all"],
# 		},
# 		{
# 			"Cmd": "healthcheck",
# 			"Value": [
# 				"CMD",
# 				"curl --fail http://localhost:3000 || exit 1",
# 			],
# 		},
# 	]}]}

# 	count(r) == 1
# }

# test_microdnf_reinstall_missing_denied {
# 	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
# 		{
# 			"Cmd": "from",
# 			"Value": ["alpine:3.5"],
# 		},
# 		{
# 			"Cmd": "run",
# 			"Value": ["microdnf reinstall bash zsh && microdnf clean all"],
# 		},
# 		{
# 			"Cmd": "healthcheck",
# 			"Value": [
# 				"CMD",
# 				"curl --fail http://localhost:3000 || exit 1",
# 			],
# 		},
# 	]}]}

# 	count(r) == 1
# }

# test_microdnf_install_allowed {
# 	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
# 		{
# 			"Cmd": "from",
# 			"Value": ["alpine:3.5"],
# 		},
# 		{
# 			"Cmd": "run",
# 			"Value": ["microdnf install --nodocs bash zsh && microdnf clean all"],
# 		},
# 		{
# 			"Cmd": "healthcheck",
# 			"Value": [
# 				"CMD",
# 				"curl --fail http://localhost:3000 || exit 1",
# 			],
# 		},
# 	]}]}

# 	count(r) == 1
# }

# write some tests for microdnf, dnf reinstall and other combinations
