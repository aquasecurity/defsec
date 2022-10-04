package functions

import "github.com/aquasecurity/defsec/pkg/scanners/azure/functions/stringFunctions"

var deploymentFuncs = map[string]func(dp DeploymentData, args ...interface{}) interface{}{
	"parameters":  Parameters,
	"deployment":  Deployment,
	"environment": Environment,
	"variables":   Variables,
}
var generalFuncs = map[string]func(...interface{}) interface{}{
	"format":       stringFunctions.Format,
	"base64":       stringFunctions.Base64,
	"base64ToJson": stringFunctions.Base64ToJson,
}

func Evaluate(deploymentProvider DeploymentData, name string, args ...interface{}) interface{} {

	if f, ok := deploymentFuncs[name]; ok {
		return f(deploymentProvider, args...)
	}

	if f, ok := generalFuncs[name]; ok {
		return f(args...)
	}

	return nil
}
