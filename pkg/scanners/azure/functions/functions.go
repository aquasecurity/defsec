package functions

import "github.com/aquasecurity/defsec/pkg/scanners/azure/functions/stringFunctions"

var deploymentFuncs = map[string]func(dp DeploymentData, args ...interface{}) interface{}{
	"parameters":  Parameters,
	"deployment":  Deployment,
	"environment": Environment,
	"variables":   Variables,
}
var generalFuncs = map[string]func(...interface{}) interface{}{

	"base64":          stringFunctions.Base64,
	"base64ToJson":    stringFunctions.Base64ToJson,
	"concat":          stringFunctions.Concat,
	"contains":        stringFunctions.Contains,
	"dataUri":         stringFunctions.DataUri,
	"dataUriToString": stringFunctions.DataUriToString,
	"empty":           stringFunctions.Empty,
	"endsWith":        stringFunctions.EndsWith,
	"format":          stringFunctions.Format,
	"guid":            stringFunctions.Guid,
	"indexOf":         stringFunctions.IndexOf,
	"join":            stringFunctions.Join,
	"lastIndexOf":     stringFunctions.LastIndexOf,
	"length":          stringFunctions.Length,
	"newGuid":         stringFunctions.NewGuid,
	"padLeft":         stringFunctions.PadLeft,
	"replace":         stringFunctions.Replace,
	"skip":            stringFunctions.Skip,
	"split":           stringFunctions.Split,
	"startsWith":      stringFunctions.StartsWith,
	"string":          stringFunctions.String,
	"substring":       stringFunctions.SubString,
	"toLower":         stringFunctions.ToLower,
	"toUpper":         stringFunctions.ToUpper,
	"trim":            stringFunctions.Trim,
	"uniqueString":    stringFunctions.UniqueString,
	"uri":             stringFunctions.Uri,
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
