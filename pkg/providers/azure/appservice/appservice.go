package appservice

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	defsecTypes.Metadata
	EnableClientCert defsecTypes.BoolValue
	Identity         struct {
		Type defsecTypes.StringValue
	}
	Authentication struct {
		Enabled defsecTypes.BoolValue
	}
	Site struct {
		EnableHTTP2       defsecTypes.BoolValue
		MinimumTLSVersion defsecTypes.StringValue
	}
}

type FunctionApp struct {
	defsecTypes.Metadata
	HTTPSOnly defsecTypes.BoolValue
}
