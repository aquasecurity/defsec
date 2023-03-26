package builtin.dockerfile.DS027

test_denied {
	r := deny with input as {"Stages": [{"Name": "ubi8:8.7", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubi8:8.7"],
		},
		{
			"Cmd": "run",
			"Value": ["set -uex &&     microdnf install -vy docker-ce"],
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
	r[_].msg == "'microdnf clean all' is missed: set -uex &&     microdnf install -vy docker-ce"
}

test_allowed {
	r := deny with input as {"Stages": [{"Name": "ubi8:8.7", "Commands": [
		{
			"Cmd": "from",
			"Value": ["ubi8:8.7"],
		},
		{
			"Cmd": "run",
			"Value": ["set -uex &&      microdnf install -vy docker-ce &&     microdnf clean all"],
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
			"Value": ["microdnf clean all && microdnf install -vy docker-ce"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'microdnf clean all' is missed: microdnf clean all && microdnf install -vy docker-ce"
}

test_multiple_install_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["microdnf install bash && microdnf clean all && microdnf install zsh"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'microdnf clean all' is missed: microdnf install bash && microdnf clean all && microdnf install zsh"
}

test_multiple_install_allowed {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["microdnf install bash && microdnf clean all && microdnf install zsh && microdnf clean all"],
		},
	]}]}

	count(r) == 0
}
