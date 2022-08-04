package v2

import (
	"github.com/aquasecurity/defsec/internal/types"
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
	types.Metadata
	Name         types.StringValue
	ProtocolType types.StringValue
	Stages       []Stage
}

type Stage struct {
	types.Metadata
	Name          types.StringValue
	AccessLogging AccessLogging
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type DomainName struct {
	types.Metadata
	Name           types.StringValue
	SecurityPolicy types.StringValue
}
