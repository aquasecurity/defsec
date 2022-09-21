package schemas

import _ "embed"

type Schema string

var (
	None     Schema = ""
	Anything Schema = `{}`
	//go:embed dockerfile.json
	Dockerfile Schema
	Cloud      Schema = `{}`
	Helm       Schema = `{}`
	Kubernetes Schema = `{}`
	RBAC       Schema = `{}`
)
