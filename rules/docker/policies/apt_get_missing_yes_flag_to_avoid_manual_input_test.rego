package builtin.dockerfile.DS021

test_denied {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install python=2.7"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'-y' flag is missed: 'apt-get install python=2.7'"
}

test_json_array_denied {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": [
				"apt-get",
				"install",
				"apt-utils",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'-y' flag is missed: 'apt-get install apt-utils'"
}

test_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get -fmy install apt-utils"],
		},
	]}]}

	count(r) == 0
}

test_with_short_flags_behind_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -fmy apt-utils"],
		},
	]}]}

	count(r) == 0
}

test_with_long_flags_behind_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install --assume-yes apt-utils"],
		},
	]}]}

	count(r) == 0
}

test_json_array_short_flag_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": [
				"apt-get",
				"-fmy",
				"install",
				"apt-utils",
			],
		},
	]}]}

	count(r) == 0
}

test_json_array_long_flag_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": [
				"apt-get",
				"--yes",
				"-q",
				"install",
				"apt-utils",
			],
		},
	]}]}

	count(r) == 0
}

test_chained_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get -y install apt-utils"],
		},
	]}]}

	count(r) == 0
}

test_flags_after_pkgs_allowed {
	r := deny with input as {"Stages": [{"Name": "debian:11-slim", "Commands": [
		{
			"Cmd": "from",
			"Value": ["debian:11-slim"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get install tzdata postgresql-10 -y && rm -rf /var/lib/apt/lists/*"],
		},
	]}]}
	count(r) == 0
}
