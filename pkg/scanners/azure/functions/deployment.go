package functions

type DeploymentData interface {
	GetParameter(name string) interface{}
	GetVariable(variableName string) interface{}
}

func Deployment(deploymentProvider DeploymentData, args ...interface{}) interface{} {
	panic("not implemented")
}

func Environment(deploymentProvider DeploymentData, args ...interface{}) interface{} {
	panic("not implemented")
}

func Variables(deploymentProvider DeploymentData, args ...interface{}) interface{} {
	panic("not implemented")
}

func Parameters(paramProvider DeploymentData, args ...interface{}) interface{} {
	if len(args) == 0 {
		return nil
	}

	paramName, ok := args[0].(string)
	if !ok {
		return nil
	}

	return paramProvider.GetParameter(paramName)

}
