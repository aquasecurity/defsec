package functions

var deploymentFuncs = map[string]func(dp DeploymentData, args ...interface{}) interface{}{
	"parameters":  Parameters,
	"deployment":  Deployment,
	"environment": Environment,
	"variables":   Variables,
}
var generalFuncs = map[string]func(...interface{}) interface{}{

	"array":           Array,
	"base64":          Base64,
	"base64ToJson":    Base64ToJson,
	"concat":          Concat,
	"contains":        Contains,
	"createArray":     CreateArray,
	"dataUri":         DataUri,
	"dataUriToString": DataUriToString,
	"empty":           Empty,
	"endsWith":        EndsWith,
	"format":          Format,
	"guid":            Guid,
	"indexOf":         IndexOf,
	"intersection":    Intersection,
	"join":            Join,
	"lastIndexOf":     LastIndexOf,
	"length":          Length,
	"max":             Max,
	"min":             Min,
	"newGuid":         NewGuid,
	"padLeft":         PadLeft,
	"range":           Range,
	"replace":         Replace,
	"skip":            Skip,
	"split":           Split,
	"startsWith":      StartsWith,
	"string":          String,
	"substring":       SubString,
	"toLower":         ToLower,
	"toUpper":         ToUpper,
	"trim":            Trim,
	"union":           Union,
	"union:":          Union,
	"uniqueString":    UniqueString,
	"uri":             Uri,
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
