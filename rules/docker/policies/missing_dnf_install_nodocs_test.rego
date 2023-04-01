package builtin.dockerfile.DS028

test_denied {
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
	r[_].msg == "'--nodocs missing': set -uex &&     dnf install -vy docker-ce &&     dnf clean all"
}

test_allowed {
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

	count(r) == 0
}

test_wrong_order_of_commands_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf clean all && dnf install -vy docker-ce"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'dnf clean all' is missed: dnf clean all && dnf install -vy docker-ce"
}

test_multiple_install_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf install bash && dnf clean all && dnf install zsh"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'dnf clean all' is missed: dnf install bash && dnf clean all && dnf install zsh"
}

test_reinstall_missing_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf reinstall bash zsh && dnf clean all"],
		},
	]}]}

	count(r) == 1
}

test_microdnf_reinstall_missing_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["microdnf reinstall bash zsh && microdnf clean all"],
		},
	]}]}

	count(r) == 1
}

test_microdnf_install_allowed {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["microdnf install --nodocs bash zsh && microdnf clean all"],
		},
	]}]}

	count(r) == 1
}


# write some tests for microdnf, dnf reinstall and other combinations
