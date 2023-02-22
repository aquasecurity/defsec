# METADATA
# title: "Duplicate aliases defined in different FROMs"
# description: "Different FROMs can't have the same alias defined."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS012
#   avd_id: AVD-DS-0012
#   severity: CRITICAL
#   short_code: no-duplicate-alias
#   recommended_action: "Change aliases to make them different"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS012

import data.lib.docker

get_duplicate_alias[output] {
	output1 := get_aliased_name[_]
	output2 := get_aliased_name[_]
	output1.arg != output2.arg

	[_, alias1] := regex.split(`\s+as\s+`, output1.arg)
	[_, alias2] := regex.split(`\s+as\s+`, output2.arg)
	alias1 == alias2
	output1.cmd.StartLine < output2.cmd.StartLine # avoid duplicates
	output := {
		"alias": alias1,
		"cmd": output1.cmd,
	}
}

get_aliased_name[output] {
	stage := input.Stages[_]
	name := stage.Name

	cmd := stage.Commands[0]

	arg = lower(name)
	contains(arg, " as ")
	output := {
		"arg": arg,
		"cmd": cmd,
	}
}

deny[res] {
	output := get_duplicate_alias[_]
	msg := sprintf("Duplicate aliases '%s' are found in different FROMs", [output.alias])
	res := result.new(msg, output.cmd)
}
