package builtin.azure.compute.azure0040

test_detects_when_disabled {
	r := deny with input as {"azure": {"compute": {"virtualmachinelist": [{"properties": {"diagnosticsprofile":{"bootdiagnostics":
	                        {"enabled": {"value": false}}}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"azure": {"compute": {"virtualmachinelist": [{"properties": {"diagnosticsprofile":{"bootdiagnostics":
                            {"enabled": {"value": true}}}}}]}}}
	count(r) == 0
}
