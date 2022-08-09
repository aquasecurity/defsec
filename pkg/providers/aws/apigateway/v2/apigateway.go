package v2

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

const (
	ProtocolTypeUnknown   string = ""
	ProtocolTypeREST      string = "REST"
	ProtocolTypeHTTP      string = "HTTP"
	ProtocolTypeWebsocket string = "WEBSOCKET"
)

type API struct {
	types2.Metadata
	Name         types2.StringValue
	ProtocolType types2.StringValue
	Stages       []Stage
}

type Stage struct {
	types2.Metadata
	Name          types2.StringValue
	AccessLogging AccessLogging
}

type AccessLogging struct {
	types2.Metadata
	CloudwatchLogGroupARN types2.StringValue
}

type DomainName struct {
	types2.Metadata
	Name           types2.StringValue
	SecurityPolicy types2.StringValue
}
