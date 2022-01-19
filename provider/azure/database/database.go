package database

import "github.com/aquasecurity/defsec/types"

type Database struct {
	types.Metadata
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	types.Metadata
	Server
}

type MySQLServer struct {
	types.Metadata
	Server
}

type PostgreSQLServer struct {
	types.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	types.Metadata
	LogCheckpoints       types.BoolValue
	ConnectionThrottling types.BoolValue
	LogConnections       types.BoolValue
}

type Server struct {
	types.Metadata
	EnableSSLEnforcement      types.BoolValue
	MinimumTLSVersion         types.StringValue
	EnablePublicNetworkAccess types.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	types.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	types.Metadata
	EmailAddresses     []types.StringValue
	DisabledAlerts     []types.StringValue
	EmailAccountAdmins types.BoolValue
}

func (p SecurityAlertPolicy) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p SecurityAlertPolicy) GetRawValue() interface{} {
	return nil
}

func (s Server) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s Server) GetRawValue() interface{} {
	return nil
}

func (s MSSQLServer) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s MSSQLServer) GetRawValue() interface{} {
	return nil
}

type ExtendedAuditingPolicy struct {
	types.Metadata
	RetentionInDays types.IntValue
}

type FirewallRule struct {
	types.Metadata
	StartIP types.StringValue
	EndIP   types.StringValue
}
