package builtin.dockerfile.DS001

test_allowed {
	r := deny with input as {"Stages": [{"Name": "openjdk:8u292-oracle", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk:8u292-oracle"],
	}]}]}

	count(r) == 0
}

# Test FROM image with latest tag
test_latest_tag_denied {
	r := deny with input as {"Stages": [{"Name": "openjdk", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk:latest"],
	}]}]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'openjdk'"
}

# Test FROM image with no tag
test_no_tag_denied {
	r := deny with input as {"Stages": [{"Name": "openjdk", "Commands": [{
		"Cmd": "from",
		"Value": ["openjdk"],
	}]}]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'openjdk'"
}

# Test FROM with scratch
test_scratch_allowed {
	r := deny with input as {"Stages": [{"Name": "scratch", "Commands": [{
		"Cmd": "from",
		"Value": ["scratch"],
	}]}]}

	count(r) == 0
}

test_with_variables_allowed {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=alpine:3.12"],
			},
		]},
		{"Name": "image", "Commands": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		]},
	]}

	count(r) == 0
}

test_with_variables_denied {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=all-in-one"],
			},
		]},
		{"Name": "image", "Commands": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'all-in-one'"
}

test_multi_stage_allowed {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.15 as builder", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.15", "as", "builder"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:3.13", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine:3.13"],
		}]},
	]}

	count(r) == 0
}

test_multi_stage_base_alias_allowed {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "build", "Commands": [{
			"Cmd": "from",
			"Value": ["dependencies", "as", "build"],
		}]},
	]}

	count(r) == 0
}

test_multi_stage_denied {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine:latest"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}

test_multi_stage_no_tag_denied {
	r := deny with input as {"Stages": [
		{"Name": "node:14.18.1-bullseye as dependencies", "Commands": [
			{
				"Cmd": "from",
				"Value": ["node:14.18.1-bullseye", "as", "dependencies"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [{
			"Cmd": "from",
			"Value": ["alpine"],
		}]},
	]}

	count(r) == 1
	r[_].msg == "Specify a tag in the 'FROM' statement for image 'alpine'"
}
