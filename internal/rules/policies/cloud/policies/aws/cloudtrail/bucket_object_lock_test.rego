package builtin.aws.cloudtrail.aws0326

test_detects_when_not_have_objectlock {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                      "s3": {"buckets": [{"name": {"value": "test"}}]}}
    }
	count(r) == 1
}

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                      "s3": {"buckets": [{"name": {"value": "test"},
                                                       "objectlockconfiguration": {"objectlockenabled": {"value": "Disabled"}}}]}}
    }
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"bucketname": {"value": "test"}}]},
                                     "s3": {"buckets": [{"name": {"value": "test"},
                                                       "objectlockconfiguration": {"objectlockenabled": {"value": "Enabled"}}}]}}
    }
	count(r) == 0
}
