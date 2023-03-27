package builtin.dockerfile.DS026

test_denied {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["busybox"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get -y update"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "Add HEALTHCHECK instruction in your Dockerfile"
}

test_allowed {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "healthcheck",
				"Value": [
					"CMD",
					"/bin/healthcheck",
				],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
	]}

	count(r) == 0
}
