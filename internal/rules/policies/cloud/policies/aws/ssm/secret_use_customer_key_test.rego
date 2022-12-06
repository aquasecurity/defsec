package builtin.aws.ssm.aws0203

test_detects_when_empty {
	r := deny with input as {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_default {
	r := deny with input as {
			"aws":{
				"ssm":{
					"secrets":[
						{
						"kmskeyid":{
							"value":"arn:aws:kms:us-east1:111122223333:key/123"
						}
						}
					]
				},
				"kms":{
					"keys":[
						{
						"manager":{
							"resource":"arn:aws:kms:us-east1:111122223333:key/123",
							"value":"AWS"
						}
						}
					]
				}
			}
			}
	count(r) == 1
}

test_when_not_empty_or_default {
    r := deny with input as {
			"aws":{
				"ssm":{
					"secrets":[
						{
						"kmskeyid":{
							"value":"arn:aws:kms:us-east1:111122223333:key/123"
						}
						}
					]
				},
				"kms":{
					"keys":[
						{
						"manager":{
							"resource":"arn:aws:kms:us-east1:111122223333:key/123",
							"value":"CUSTOMER"
						}
						}
					]
				}
			}
			}
	count(r) == 0	
}
