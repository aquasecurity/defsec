# METADATA
# custom:
#   input:
#     selector:
#     - type: dockerfile
package lib.docker

from[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "from"
}

add[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "add"
}

run[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "run"
}

copy[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "copy"
}

stage_copies[stage] = copies {
	stage := input.Stages[_]
	copies := [copy | copy := stage.Commands[_]; copy.Cmd == "copy"]
}

entrypoint[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage] = entrypoints {
	stage := input.Stages[_]
	entrypoints := [entrypoint | entrypoint := stage.Commands[_]; entrypoint.Cmd == "entrypoint"]
}

stage_cmd[stage] = cmds {
	stage := input.Stages[_]
	cmds := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "cmd"]
}

stage_healthcheck[stage] = hlthchecks {
	stage := input.Stages[_]
	hlthchecks := [hlthcheck | hlthcheck := stage.Commands[_]; hlthcheck.Cmd == "healthcheck"]
}

stage_user[stage] = users {
	stage := input.Stages[_]
	users := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "user"]
}

expose[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "expose"
}

user[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "user"
}

workdir[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "workdir"
}

healthcheck[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "healthcheck"
}
