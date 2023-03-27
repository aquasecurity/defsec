package builtin.kubernetes.KCV0084

test_validate_iptables_util_chains_set_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletMakeIptablesUtilChainsArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_iptables_util_chains_set_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletMakeIptablesUtilChainsArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}
