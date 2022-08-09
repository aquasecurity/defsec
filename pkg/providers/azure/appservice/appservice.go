package appservice

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	types2.Metadata
	EnableClientCert types2.BoolValue
	Identity         struct {
		Type types2.StringValue
	}
	Authentication struct {
		Enabled types2.BoolValue
	}
	Site struct {
		EnableHTTP2       types2.BoolValue
		MinimumTLSVersion types2.StringValue
	}
}

type FunctionApp struct {
	types2.Metadata
	HTTPSOnly types2.BoolValue
}
