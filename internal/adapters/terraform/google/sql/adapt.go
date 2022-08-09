package sql

import (
	"strconv"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
)

func Adapt(modules terraform.Modules) sql.SQL {
	return sql.SQL{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform.Modules) []sql.DatabaseInstance {
	var instances []sql.DatabaseInstance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_sql_database_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *terraform.Block) sql.DatabaseInstance {

	instance := sql.DatabaseInstance{
		Metadata:        resource.GetMetadata(),
		DatabaseVersion: resource.GetAttribute("database_version").AsStringValueOrDefault("", resource),
		IsReplica:       types2.BoolDefault(false, resource.GetMetadata()),
		Settings: sql.Settings{
			Metadata: resource.GetMetadata(),
			Flags: sql.Flags{
				Metadata:                        resource.GetMetadata(),
				LogTempFileSize:                 types2.IntDefault(-1, resource.GetMetadata()),
				LocalInFile:                     types2.BoolDefault(false, resource.GetMetadata()),
				ContainedDatabaseAuthentication: types2.BoolDefault(true, resource.GetMetadata()),
				CrossDBOwnershipChaining:        types2.BoolDefault(true, resource.GetMetadata()),
				LogCheckpoints:                  types2.BoolDefault(false, resource.GetMetadata()),
				LogConnections:                  types2.BoolDefault(false, resource.GetMetadata()),
				LogDisconnections:               types2.BoolDefault(false, resource.GetMetadata()),
				LogLockWaits:                    types2.BoolDefault(false, resource.GetMetadata()),
				LogMinMessages:                  types2.StringDefault("", resource.GetMetadata()),
				LogMinDurationStatement:         types2.IntDefault(-1, resource.GetMetadata()),
			},
			Backups: sql.Backups{
				Metadata: resource.GetMetadata(),
				Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			},
			IPConfiguration: sql.IPConfiguration{
				Metadata:           resource.GetMetadata(),
				RequireTLS:         types2.BoolDefault(false, resource.GetMetadata()),
				EnableIPv4:         types2.BoolDefault(true, resource.GetMetadata()),
				AuthorizedNetworks: nil,
			},
		},
	}

	if attr := resource.GetAttribute("master_instance_name"); attr.IsNotNil() {
		instance.IsReplica = types2.Bool(true, attr.GetMetadata())
	}

	if settingsBlock := resource.GetBlock("settings"); settingsBlock.IsNotNil() {
		instance.Settings.Metadata = settingsBlock.GetMetadata()
		if blocks := settingsBlock.GetBlocks("database_flags"); len(blocks) > 0 {
			adaptFlags(blocks, &instance.Settings.Flags)
		}
		if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNotNil() {
			instance.Settings.Backups.Metadata = backupBlock.GetMetadata()
			backupConfigEnabledAttr := backupBlock.GetAttribute("enabled")
			instance.Settings.Backups.Enabled = backupConfigEnabledAttr.AsBoolValueOrDefault(false, backupBlock)
		}
		if settingsBlock.HasChild("ip_configuration") {
			instance.Settings.IPConfiguration = adaptIPConfig(settingsBlock.GetBlock("ip_configuration"))
		}
	}
	return instance
}

//nolint
func adaptFlags(resources terraform.Blocks, flags *sql.Flags) {
	for _, resource := range resources {

		nameAttr := resource.GetAttribute("name")
		valueAttr := resource.GetAttribute("value")

		if !nameAttr.IsString() || valueAttr.IsNil() {
			continue
		}

		switch nameAttr.Value().AsString() {
		case "log_temp_files":
			if logTempInt, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogTempFileSize = types2.Int(logTempInt, nameAttr.GetMetadata())
			}
		case "log_min_messages":
			flags.LogMinMessages = valueAttr.AsStringValueOrDefault("", resource)
		case "log_min_duration_statement":
			if logMinDS, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogMinDurationStatement = types2.Int(logMinDS, nameAttr.GetMetadata())
			}
		case "local_infile":
			flags.LocalInFile = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_checkpoints":
			flags.LogCheckpoints = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_connections":
			flags.LogConnections = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_disconnections":
			flags.LogDisconnections = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_lock_waits":
			flags.LogLockWaits = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "contained database authentication":
			flags.ContainedDatabaseAuthentication = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "cross db ownership chaining":
			flags.CrossDBOwnershipChaining = types2.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		}
	}
}

func adaptIPConfig(resource *terraform.Block) sql.IPConfiguration {
	var authorizedNetworks []struct {
		Name types2.StringValue
		CIDR types2.StringValue
	}

	tlsRequiredAttr := resource.GetAttribute("require_ssl")
	tlsRequiredVal := tlsRequiredAttr.AsBoolValueOrDefault(false, resource)

	ipv4enabledAttr := resource.GetAttribute("ipv4_enabled")
	ipv4enabledVal := ipv4enabledAttr.AsBoolValueOrDefault(true, resource)

	authNetworksBlocks := resource.GetBlocks("authorized_networks")
	for _, authBlock := range authNetworksBlocks {
		nameVal := authBlock.GetAttribute("name").AsStringValueOrDefault("", authBlock)
		cidrVal := authBlock.GetAttribute("value").AsStringValueOrDefault("", authBlock)

		authorizedNetworks = append(authorizedNetworks, struct {
			Name types2.StringValue
			CIDR types2.StringValue
		}{
			Name: nameVal,
			CIDR: cidrVal,
		})
	}

	return sql.IPConfiguration{
		Metadata:           resource.GetMetadata(),
		RequireTLS:         tlsRequiredVal,
		EnableIPv4:         ipv4enabledVal,
		AuthorizedNetworks: authorizedNetworks,
	}
}
