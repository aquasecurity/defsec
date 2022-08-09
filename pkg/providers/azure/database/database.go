package database

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Database struct {
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	types2.Metadata
	Server
}

type MySQLServer struct {
	types2.Metadata
	Server
}

type PostgreSQLServer struct {
	types2.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	types2.Metadata
	LogCheckpoints       types2.BoolValue
	ConnectionThrottling types2.BoolValue
	LogConnections       types2.BoolValue
}

type Server struct {
	types2.Metadata
	EnableSSLEnforcement      types2.BoolValue
	MinimumTLSVersion         types2.StringValue
	EnablePublicNetworkAccess types2.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	types2.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	types2.Metadata
	EmailAddresses     []types2.StringValue
	DisabledAlerts     []types2.StringValue
	EmailAccountAdmins types2.BoolValue
}

type ExtendedAuditingPolicy struct {
	types2.Metadata
	RetentionInDays types2.IntValue
}

type FirewallRule struct {
	types2.Metadata
	StartIP types2.StringValue
	EndIP   types2.StringValue
}
