package sql

import (
	"strings"

	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SQL struct {
	Instances []DatabaseInstance
}

const (
	DatabaseFamilyMySQL     = "MYSQL"
	DatabaseFamilyPostgres  = "POSTGRES"
	DatabaseFamilySQLServer = "SQLSERVER"
)

const (
	DatabaseVersionMySQL_5_6                 = "MYSQL_5_6"
	DatabaseVersionMySQL_5_7                 = "MYSQL_5_7"
	DatabaseVersionMySQL_8_0                 = "MYSQL_8_0"
	DatabaseVersionPostgres_9_6              = "POSTGRES_9_6"
	DatabaseVersionPostgres_10               = "POSTGRES_10"
	DatabaseVersionPostgres_11               = "POSTGRES_11"
	DatabaseVersionPostgres_12               = "POSTGRES_12"
	DatabaseVersionPostgres_13               = "POSTGRES_13"
	DatabaseVersionSQLServer_2017_STANDARD   = "SQLSERVER_2017_STANDARD"
	DatabaseVersionSQLServer_2017_ENTERPRISE = "SQLSERVER_2017_ENTERPRISE"
	DatabaseVersionSQLServer_2017_EXPRESS    = "SQLSERVER_2017_EXPRESS"
	DatabaseVersionSQLServer_2017_WEB        = "SQLSERVER_2017_WEB"
)

type DatabaseInstance struct {
	types2.Metadata
	DatabaseVersion types2.StringValue
	Settings        Settings
	IsReplica       types2.BoolValue
}

type Settings struct {
	types2.Metadata
	Flags           Flags
	Backups         Backups
	IPConfiguration IPConfiguration
}
type Flags struct {
	types2.Metadata
	LogTempFileSize                 types2.IntValue
	LocalInFile                     types2.BoolValue
	ContainedDatabaseAuthentication types2.BoolValue
	CrossDBOwnershipChaining        types2.BoolValue
	LogCheckpoints                  types2.BoolValue
	LogConnections                  types2.BoolValue
	LogDisconnections               types2.BoolValue
	LogLockWaits                    types2.BoolValue
	LogMinMessages                  types2.StringValue // FATAL, PANIC, LOG, ERROR, WARN
	LogMinDurationStatement         types2.IntValue
}

type Backups struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type IPConfiguration struct {
	types2.Metadata
	RequireTLS         types2.BoolValue
	EnableIPv4         types2.BoolValue
	AuthorizedNetworks []struct {
		Name types2.StringValue
		CIDR types2.StringValue
	}
}

func (i *DatabaseInstance) DatabaseFamily() string {
	return strings.Split(i.DatabaseVersion.Value(), "_")[0]
}
