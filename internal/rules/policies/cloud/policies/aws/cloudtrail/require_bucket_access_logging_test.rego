package builtin.aws.cloudtrail.aws0322

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                      "s3": {"buckets": [{"name": {"value": "test"},
                                                       "logging": {"enabled": {"value": false}}}]}}
    }
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                     "s3": {"buckets": [{"name": {"value": "test"},
                                                       "logging": {"enabled": {"value": true}}}]}}
    }
	count(r) == 0
}
