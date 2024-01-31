package builtin.aws.elasticache.aws0196

test_detects_when_description_not_have {
	r := deny with input as {"aws": {"elasticache": {"securitygroups": [{"description": {"value": ""}}]}}}
	count(r) == 1
}

test_when_description_have {
	r := deny with input as {"aws": {"elasticache": {"securitygroups": [{"description": {"value": "description"}}]}}}
	count(r) == 0
}
