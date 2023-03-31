package builtin.dockerfile.DS022

test_denied {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "maintainer",
			"Value": ["admin@example.com"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "MAINTAINER should not be used: 'MAINTAINER admin@example.com'"
}

test_allowed {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [{
		"Cmd": "from",
		"Value": ["fedora:27"],
	}]}]}

	count(r) == 0
}
