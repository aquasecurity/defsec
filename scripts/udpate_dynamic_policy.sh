#!/bin/bash
DYNAMIC_REGO_FOLDER=./internal/rules/kubernetes/policies/dynamic
sed -i.bak "s|{}|$1|" $DYNAMIC_REGO_FOLDER/outdated_api.rego && rm $DYNAMIC_REGO_FOLDER/outdated_api.rego.bak
# used for test , remove before release
cat  $DYNAMIC_REGO_FOLDER/outdated_api.rego
