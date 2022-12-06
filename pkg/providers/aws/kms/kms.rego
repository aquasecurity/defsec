package kms.rego

is_aws_managed(kmskeyid) := true{
	key := input.aws.kms.keys[_]
	kmskeyid == key.metadata.resource
	key.manager.value == "AWS"
}
