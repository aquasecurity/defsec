package functions

var deploymentFuncs = map[string]func(dp DeploymentData, args ...interface{}) interface{}{
	"parameters":  Parameters,
	"deployment":  Deployment,
	"environment": Environment,
	"variables":   Variables,
}
var generalFuncs = map[string]func(...interface{}) interface{}{

	"and":               And,
	"array":             Array,
	"base64":            Base64,
	"base64ToJson":      Base64ToJson,
	"bool":              Bool,
	"coalesce":          Coalesce,
	"concat":            Concat,
	"contains":          Contains,
	"createArray":       CreateArray,
	"dataUri":           DataUri,
	"dataUriToString":   DataUriToString,
	"dateTimeAdd":       DateTimeAdd,
	"dateTimeFromEpoch": DateTimeFromEpoch,
	"dateTimeToEpoch":   DateTimeToEpoch,
	"empty":             Empty,
	"endsWith":          EndsWith,
	"equals":            Equals,
	"false":             False,
	"format":            Format,
	"greater":           Greater,
	"greaterOrEquals":   GreaterOrEquals,
	"guid":              Guid,
	"if":                If,
	"indexOf":           IndexOf,
	"intersection":      Intersection,
	"join":              Join,
	"lastIndexOf":       LastIndexOf,
	"length":            Length,
	"less":              Less,
	"lessOrEquals":      LessOrEquals,
	"max":               Max,
	"min":               Min,
	"newGuid":           NewGuid,
	"not":               Not,
	"or":                Or,
	"padLeft":           PadLeft,
	"range":             Range,
	"replace":           Replace,
	"skip":              Skip,
	"split":             Split,
	"startsWith":        StartsWith,
	"string":            String,
	"substring":         SubString,
	"toLower":           ToLower,
	"toUpper":           ToUpper,
	"trim":              Trim,
	"true":              True,
	"union":             Union,
	"union:":            Union,
	"uniqueString":      UniqueString,
	"uri":               Uri,
	"utcNow":            UTCNow,

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
