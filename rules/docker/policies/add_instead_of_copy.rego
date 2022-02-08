package appshield.dockerfile.DS005

import data.lib.docker

__rego_metadata__ := {
	"id": "DS005",
	"avd_id": "AVD-DS-0005",
	"title": "ADD instead of COPY",
	"short_code": "use-copy-over-add",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
	"recommended_actions": "Use COPY instead of ADD",
	"url": "https://docs.docker.com/engine/reference/builder/#add",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_add[args] {
	add := docker.add[_]
	args := concat(" ", add.Value)

	not contains(args, ".tar")
}

deny[res] {
	args := get_add[_]
	res := sprintf("Consider using 'COPY %s' command instead of 'ADD %s'", [args, args])
}
