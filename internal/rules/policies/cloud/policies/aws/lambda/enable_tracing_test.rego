package builtin.aws.lambda.aws0311

test_detects_when_active_tracing {
	r := deny with input as {"aws": {"lambda": {"functions": [{"tracing": {"mode": {"value": "Active"}}}]}}}
	count(r) == 0
}

test_when_no_active_tracing {
	r := deny with input as {"aws": {"lambda": {"functions": [{"tracing": {"mode": {"value": "PassThrough"}}}]}}}
	count(r) == 1
}