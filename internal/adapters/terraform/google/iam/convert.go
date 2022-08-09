package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func ParsePolicyBlock(block *terraform.Block) []iam.Binding {
	var bindings []iam.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		binding := iam.Binding{
			Metadata:                      bindingBlock.GetMetadata(),
			Members:                       nil,
			Role:                          bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock),
			IncludesDefaultServiceAccount: types2.BoolDefault(false, bindingBlock.GetMetadata()),
		}
		membersAttr := bindingBlock.GetAttribute("members")
		members := membersAttr.AsStringValues().AsStrings()
		for _, member := range members {
			binding.Members = append(binding.Members, types2.String(member, membersAttr.GetMetadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
