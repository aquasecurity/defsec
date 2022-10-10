package builtin.aws.rds.aws0176

test_mixed_commands_denied {
    r := deny with input as {
        "aws": {
            "rds": {
                "instances": [
                    {
                        "engine": { "value": "postgres" },
                        "iamauthenabled": { "value": true}
                    }
                ]
            }
        }
    }
    count(r) == 1
}