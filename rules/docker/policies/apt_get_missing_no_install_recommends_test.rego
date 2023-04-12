package builtin.dockerfile.DS029

test_denied {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y python=2.7"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'--no-install-recommends' flag is missed: 'apt-get install -y python=2.7'"
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
				"-y",
				"apt-utils",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'--no-install-recommends' flag is missed: 'apt-get install -y apt-utils'"
}

test_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get -fmy install --no-install-recommends apt-utils"],
		},
	]}]}

	count(r) == 0
}

test_with_flag_behind_allowed {
	r := deny with input as {"Stages": [{"Name": "node:12", "Commands": [
		{
			"Cmd": "from",
			"Value": ["node:12"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get --no-install-recommends install -fmy apt-utils"],
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
				"--no-install-recommends",
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
			"Value": ["apt-get update && apt-get --no-install-recommends -y install apt-utils"],
		},
	]}]}

	count(r) == 0
}
