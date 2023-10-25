package terraform

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
	"golang.org/x/exp/slices"
)

type values map[string]cty.Value

func createPresetValues(b *Block) values {
	presets := make(values)

	// here we set up common "id" values that are set by the provider - this ensures all blocks have a default
	// referencable id/arn. this isn't perfect, but the only way to link blocks in certain circumstances.
	presets["id"] = cty.StringVal(b.ID())

	if strings.HasPrefix(b.TypeLabel(), "aws_") {
		presets["arn"] = cty.StringVal(b.ID())
	}

	// workaround for weird iam feature
	switch b.TypeLabel() {
	case "aws_iam_policy_document":
		presets["json"] = cty.StringVal(b.ID())
	}

	return presets

}

func postProcessValues(b *Block, input values) values {

	// alias id to "bucket" (bucket name) for s3 bucket resources
	if strings.HasPrefix(b.TypeLabel(), "aws_s3_bucket") {
		overrideIdOrSetAttr("bucket", input, b)
	} else if slices.Contains([]string{"aws_iam_role", "aws_iam_group", "aws_iam_user"}, "") {
		// The resource ID is equal to the name attribute
		// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role#id
		overrideIdOrSetAttr("name", input, b)
	}
	return input
}

func overrideIdOrSetAttr(attributeName string, input values, b *Block) {
	if name, ok := input[attributeName]; ok {
		input["id"] = name
	} else {
		input[attributeName] = cty.StringVal(b.ID())
	}
}
