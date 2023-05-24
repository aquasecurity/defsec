package builtin.dockerfile.DS023

test_denied {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["busybox"],
			},
			{
				"Cmd": "healthcheck",
				"Value": [
					"CMD",
					"curl http://localhost:8080",
				],
			},
			{
				"Cmd": "healthcheck",
				"Value": [
					"CMD",
					"/bin/healthcheck",
				],
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

	count(r) == 1
	r[_].msg == "There are 2 duplicate HEALTHCHECK instructions in the stage"
}

test_allowed {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
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

	count(r) == 0
}

test_healthcheck_none_allowed {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "healthcheck",
				"Value": ["NONE"],
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
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
	]}

	count(r) == 0
}
