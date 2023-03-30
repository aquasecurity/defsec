package builtin.aws.appmesh.aws0337

test_detects_when_allow_access {
	r := deny with input as {"aws": {"appmesh": {"meshes": [{"spec": {"egressfilter": {"type": {"value": "ALLOW_ALL"}}}}]}}}
	count(r) == 1
}

test_when_not_allow_access {
	r := deny with input as {"aws": {"appmesh": {"meshes": [{"spec": {"egressfilter": {"type": {"value": "DROP_ALL"}}}}]}}}
	count(r) == 0
}
