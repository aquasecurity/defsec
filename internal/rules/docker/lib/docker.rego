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

stage_copies[stage_name] = copies {
	stage := input.Stages[_]
	stage_name := stage.Name
	copies := [copy | copy := stage.Commands[_]; copy.Cmd == "copy"]
}

entrypoint[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage_name] = entrypoints {
	stage := input.Stages[_]
	stage_name := stage.Name
	entrypoints := [entrypoint | entrypoint := stage.Commands[_]; entrypoint.Cmd == "entrypoint"]
}

stage_cmd[stage_name] = cmds {
	stage := input.Stages[_]
	stage_name := stage.Name
	cmds := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "cmd"]
}

stage_healthcheck[stage_name] = hlthchecks {
	stage := input.Stages[_]
	stage_name := stage.Name
	hlthchecks := [hlthcheck | hlthcheck := stage.Commands[_]; hlthcheck.Cmd == "healthcheck"]
}

stage_user[stage_name] = users {
	stage := input.Stages[_]
	stage_name := stage.Name
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

result(msg, cmd) = result {
	result := {
		"msg": msg,
		"startline": object.get(cmd, "StartLine", 0),
		"endline": object.get(cmd, "EndLine", 0),
		"filepath": object.get(cmd, "Path", ""),
	}
}
