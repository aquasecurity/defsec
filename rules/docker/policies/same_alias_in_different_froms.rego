package appshield.dockerfile.DS012

__rego_metadata__ := {
	"id": "DS012",
	"avd_id": "AVD-DS-0012",
	"title": "Duplicate aliases defined in different FROMs",
	"short_code": "no-duplicate-alias",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Different FROMs can't have the same alias defined.",
	"recommended_actions": "Change aliases to make them different",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_duplicate_alias[alias1] {
	name1 := get_aliased_name[_]
	name2 := get_aliased_name[_]
	name1 != name2

	[_, alias1] := regex.split(`\s+as\s+`, name1)
	[_, alias2] := regex.split(`\s+as\s+`, name2)
	alias1 == alias2
}

get_aliased_name[arg] {
	some name
	input.stages[name]

	arg = lower(name)
	contains(arg, " as ")
}

deny[res] {
	alias := get_duplicate_alias[_]
	res := sprintf("Duplicate aliases '%s' are found in different FROMs", [alias])
}
