package lib.docker

from[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "from"
}

add[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "add"
}

run[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "run"
}

copy[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "copy"
}

stage_copies[stage_name] = copies {
	stage := input.stages[stage_name]
	copies := [copy | copy := stage[_]; copy.Cmd == "copy"]
}

entrypoint[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage_name] = entrypoints {
	stage := input.stages[stage_name]
	entrypoints := [entrypoint | entrypoint := stage[_]; entrypoint.Cmd == "entrypoint"]
}

stage_cmd[stage_name] = cmds {
	stage := input.stages[stage_name]
	cmds := [cmd | cmd := stage[_]; cmd.Cmd == "cmd"]
}

stage_healthcheck[stage_name] = hlthchecks {
	stage := input.stages[stage_name]
	hlthchecks := [hlthcheck | hlthcheck := stage[_]; hlthcheck.Cmd == "healthcheck"]
}

stage_user[stage_name] = users {
	stage := input.stages[stage_name]
	users := [cmd | cmd := stage[_]; cmd.Cmd == "user"]
}

expose[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "expose"
}

user[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "user"
}

workdir[instruction] {
	instruction := input.stages[_][_]
	instruction.Cmd == "workdir"
}

startline(x) = 0 { not x.StartLine }
startline(x) = x.StartLine { x.StartLine }

endline(x) = 0 { not x.EndLine }
endline(x) = x.EndLine { x.EndLine }
