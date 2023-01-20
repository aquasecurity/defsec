package builtin.aws.appmesh.aws0338

test_detects_when_disabled_strict{
	r := deny with input as {"aws": {"appmesh": {"meshes": [{"virtualgateways": [{"spec": {"listeners": [{"tls": {"mode": {"value": "STRICT"}}},
                                                                                                          {"tls": {"mode": {"value": "DISABLED"}}}]}}]}]}}}
    count(r) == 1
}

test_when_enabled_strict {
	r := deny with input as {"aws": {"appmesh": {"meshes": [{"virtualgateways": [{"spec": {"listeners": [{"tls": {"mode": {"value": "STRICT"}}},
                                                                                                          {"tls": {"mode": {"value": "STRICT"}}}]}}]}]}}}                      
	count(r) == 0
}
