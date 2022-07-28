package iam

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/google/uuid"
)

func adaptUsers(modules terraform.Modules) []iam.User {
	userMap, policyMap := mapUsers(modules)
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_user_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		userAttr := policyBlock.GetAttribute("user")
		if userAttr.IsNil() {
			continue
		}
		userBlock, err := modules.GetReferencedBlock(userAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		user := userMap[userBlock.ID()]
		user.Policies = append(user.Policies, policy)
		userMap[userBlock.ID()] = user
	}
	for _, block := range modules.GetResourcesByType("aws_iam_access_key") {
		if userAttr := block.GetAttribute("user"); userAttr.IsString() {
			var found bool
			for _, user := range userMap {
				if user.Name.EqualTo(userAttr.Value().AsString()) {
					found = true
					break
				}
			}
			if found {
				continue
			}
			key, err := adaptAccessKey(block)
			if err != nil {
				continue
			}
			userMap[uuid.NewString()] = iam.User{
				Metadata:   block.GetMetadata(),
				Name:       userAttr.AsStringValueOrDefault("", block),
				AccessKeys: []iam.AccessKey{*key},
				LastAccess: types.TimeUnresolvable(block.GetMetadata()),
			}
		}
	}

	var output []iam.User
	for _, user := range userMap {
		output = append(output, user)
	}
	return output
}

func mapUsers(modules terraform.Modules) (map[string]iam.User, map[string]struct{}) {
	userMap := make(map[string]iam.User)
	policyMap := make(map[string]struct{})
	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		user := iam.User{
			Metadata:   userBlock.GetMetadata(),
			Name:       userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock),
			LastAccess: types.TimeUnresolvable(userBlock.GetMetadata()),
		}

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy_attachment") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_access_key") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); (userAttr.IsString() && userAttr.Equals(user.Name.Value())) || userAttr.ReferencesBlock(userBlock) {
				key, err := adaptAccessKey(block)
				if err != nil {
					continue
				}
				user.AccessKeys = append(user.AccessKeys, *key)
			}
		}

		userMap[userBlock.ID()] = user
	}
	return userMap, policyMap

}

func adaptAccessKey(block *terraform.Block) (*iam.AccessKey, error) {

	active := types.BoolDefault(true, block.GetMetadata())
	if activeAttr := block.GetAttribute("status"); activeAttr.IsString() {
		active = types.Bool(activeAttr.Equals("Inactive"), activeAttr.GetMetadata())
	}

	key := iam.AccessKey{
		Metadata:     block.GetMetadata(),
		AccessKeyId:  types.StringUnresolvable(block.GetMetadata()),
		CreationDate: types.TimeUnresolvable(block.GetMetadata()),
		LastAccess:   types.TimeUnresolvable(block.GetMetadata()),
		Active:       active,
	}
	return &key, nil
}
