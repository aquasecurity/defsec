package builtin.aws.cloudtrail.aws0326

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                      "s3": {"buckets": [{"name": {"value": "test"},
                                                       "objectlockconfiguration": {"objectlockenabled": {"value": "disabled"}}}]}}
    }
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                     "s3": {"buckets": [{"name": {"value": "test"},
                                                       "objectlockconfiguration": {"objectlockenabled": {"value": "enabled"}}}]}}
    }
	count(r) == 0
}
