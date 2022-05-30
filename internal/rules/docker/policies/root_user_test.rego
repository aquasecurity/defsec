package builtin.dockerfile.DS002

import data.lib.docker

test_not_root_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{
			"Cmd": "user",
			"Value": ["user1", "user2"],
			"StartLine": 1,
			"Stage": 1,
		}],
	}]}

	count(r) == 0
}

test_last_non_root_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [
			{
				"Cmd": "user",
				"Value": ["root"],
				"StartLine": 1,
				"Stage": 1,
			},
			{
				"Cmd": "user",
				"Value": ["user1"],
				"StartLine": 2,
				"Stage": 1,
			},
		],
	}]}

	count(r) == 0
}

test_no_user_cmd_denied {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{
			"Cmd": "expose",
			"Value": [22],
			"StartLine": 1,
			"Stage": 1,
		}],
	}]}

	count(r) == 1
	startswith(r[_].msg, "Specify at least 1 USER command in Dockerfile")
}

test_last_root_denied {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
				"StartLine": 1,
				"Stage": 1,
			},
			{
				"Cmd": "user",
				"Value": ["user1"],
				"StartLine": 2,
				"Stage": 1,
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
				"StartLine": 3,
				"Stage": 1,
			},
			{
				"Cmd": "user",
				"Value": ["root"],
				"StartLine": 4,
				"Stage": 1,
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
				"StartLine": 5,
				"Stage": 1,
			},
		],
	}]}

	count(r) > 0
	startswith(r[_].msg, "Last USER command in Dockerfile should not be 'root'")
}

test_last_root_case_2 {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [
			{
				"Cmd": "user",
				"Value": ["user1"],
				"StartLine": 1,
				"Stage": 1,
			},
			{
				"Cmd": "user",
				"Value": ["root"],
				"StartLine": 2,
				"Stage": 1,
			},
		],
	}]}

	count(r) > 0
	startswith(r[_].msg, "Last USER command in Dockerfile should not be 'root'")
}

test_empty_user_denied {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{
			"Cmd": "user",
			"Value": [],
			"StartLine": 1,
			"Stage": 1,
		}],
	}]}

	count(r) == 1
	startswith(r[_].msg, "Specify at least 1 USER command in Dockerfile")
}

test_multi_stage_build_allowed_if_last_stage_uses_non_root {
	r := deny with input as {"Stages": [
		{
			"Name": "alpine:3.13",
			"Commands": [{
				"Cmd": "user",
				"Value": ["root"],
				"StartLine": 1,
				"Stage": 1,
			}],
		},
		{
			"Name": "alpine:3.14",
			"Commands": [{
				"Cmd": "user",
				"Value": ["user1"],
				"StartLine": 2,
				"Stage": 2,
			}],
		},
	]}

	count(r) == 0
}

test_multi_stage_build_denied_if_last_stage_does_not_specify_user {
	r := deny with input as {"Stages": [
		{
			"Name": "alpine:3.13",
			"Commands": [{
				"Cmd": "user",
				"Value": ["root"],
				"StartLine": 1,
				"Stage": 1,
			}],
		},
		{
			"Name": "alpine:3.14",
			"Commands": [{
				"Cmd": "copy",
				"Value": ["blah.zip"],
				"StartLine": 2,
				"Stage": 2,
			}],
		},
	]}

	count(r) == 1
}
