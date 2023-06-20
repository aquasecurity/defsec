package storage

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) storage.Storage {
	accounts, containers, networkRules := adaptAccounts(modules)

	orphanAccount := storage.Account{
		Metadata:     defsecTypes.NewUnmanagedMetadata(),
		NetworkRules: adaptOrphanNetworkRules(modules, networkRules),
		EnforceHTTPS: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		Containers:   adaptOrphanContainers(modules, containers),
		QueueProperties: storage.QueueProperties{
			Metadata:      defsecTypes.NewUnmanagedMetadata(),
			EnableLogging: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		},
		MinimumTLSVersion: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
	}

	accounts = append(accounts, orphanAccount)

	return storage.Storage{
		Accounts: accounts,
	}
}

func adaptOrphanContainers(modules terraform.Modules, containers []string) (orphans []storage.Container) {
	accountedFor := make(map[string]bool)
	for _, container := range containers {
		accountedFor[container] = true
	}
	for _, module := range modules {
		for _, containerResource := range module.GetResourcesByType("azurerm_storage_container") {
			if _, ok := accountedFor[containerResource.ID()]; ok {
				continue
			}
			orphans = append(orphans, adaptContainer(containerResource))
		}
	}

	return orphans
}

func adaptOrphanNetworkRules(modules terraform.Modules, networkRules []string) (orphans []storage.NetworkRule) {
	accountedFor := make(map[string]bool)
	for _, networkRule := range networkRules {
		accountedFor[networkRule] = true
	}

	for _, module := range modules {
		for _, networkRuleResource := range module.GetResourcesByType("azurerm_storage_account_network_rules") {
			if _, ok := accountedFor[networkRuleResource.ID()]; ok {
				continue
			}

			orphans = append(orphans, adaptNetworkRule(networkRuleResource))
		}
	}

	return orphans
}

func adaptAccounts(modules terraform.Modules) ([]storage.Account, []string, []string) {
	var accounts []storage.Account
	var accountedForContainers []string
	var accountedForNetworkRules []string

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_storage_account") {
			account := adaptAccount(resource)
			containerResource := module.GetReferencingResources(resource, "azurerm_storage_container", "storage_account_name")
			for _, containerBlock := range containerResource {
				accountedForContainers = append(accountedForContainers, containerBlock.ID())
				account.Containers = append(account.Containers, adaptContainer(containerBlock))
			}
			networkRulesResource := module.GetReferencingResources(resource, "azurerm_storage_account_network_rules", "storage_account_name")
			for _, networkRuleBlock := range networkRulesResource {
				accountedForNetworkRules = append(accountedForNetworkRules, networkRuleBlock.ID())
				account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkRuleBlock))
			}
			for _, queueBlock := range module.GetReferencingResources(resource, "azurerm_storage_queue", "storage_account_name") {
				queue := storage.Queue{
					Metadata: queueBlock.GetMetadata(),
					Name:     queueBlock.GetAttribute("name").AsStringValueOrDefault("", queueBlock),
				}
				account.Queues = append(account.Queues, queue)
			}
			accounts = append(accounts, account)
		}
	}

	return accounts, accountedForContainers, accountedForNetworkRules
}

func adaptAccount(resource *terraform.Block) storage.Account {
	account := storage.Account{
		Metadata:     resource.GetMetadata(),
		NetworkRules: nil,
		EnforceHTTPS: defsecTypes.BoolDefault(true, resource.GetMetadata()),
		Containers:   nil,
		QueueProperties: storage.QueueProperties{
			Metadata:      resource.GetMetadata(),
			EnableLogging: defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MinimumTLSVersion: defsecTypes.StringDefault("TLS1_2", resource.GetMetadata()),
	}

	networkRulesBlocks := resource.GetBlocks("network_rules")
	for _, networkBlock := range networkRulesBlocks {
		account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkBlock))
	}

	httpsOnlyAttr := resource.GetAttribute("enable_https_traffic_only")
	account.EnforceHTTPS = httpsOnlyAttr.AsBoolValueOrDefault(true, resource)

	queuePropertiesBlock := resource.GetBlock("queue_properties")
	if queuePropertiesBlock.IsNotNil() {
		account.QueueProperties.Metadata = queuePropertiesBlock.GetMetadata()
		loggingBlock := queuePropertiesBlock.GetBlock("logging")
		if loggingBlock.IsNotNil() {
			account.QueueProperties.EnableLogging = defsecTypes.Bool(true, loggingBlock.GetMetadata())
		}
	}

	minTLSVersionAttr := resource.GetAttribute("min_tls_version")
	account.MinimumTLSVersion = minTLSVersionAttr.AsStringValueOrDefault("TLS1_0", resource)
	return account
}

func adaptContainer(resource *terraform.Block) storage.Container {
	accessTypeAttr := resource.GetAttribute("container_access_type")
	publicAccess := defsecTypes.StringDefault(storage.PublicAccessOff, resource.GetMetadata())

	if accessTypeAttr.Equals("blob") {
		publicAccess = defsecTypes.String(storage.PublicAccessBlob, accessTypeAttr.GetMetadata())
	} else if accessTypeAttr.Equals("container") {
		publicAccess = defsecTypes.String(storage.PublicAccessContainer, accessTypeAttr.GetMetadata())
	}

	return storage.Container{
		Metadata:     resource.GetMetadata(),
		PublicAccess: publicAccess,
	}
}

func adaptNetworkRule(resource *terraform.Block) storage.NetworkRule {
	var allowByDefault defsecTypes.BoolValue
	var bypass []defsecTypes.StringValue

	defaultActionAttr := resource.GetAttribute("default_action")

	if defaultActionAttr.IsNotNil() {
		allowByDefault = defsecTypes.Bool(defaultActionAttr.Equals("Allow", terraform.IgnoreCase), defaultActionAttr.GetMetadata())
	} else {
		allowByDefault = defsecTypes.BoolDefault(false, resource.GetMetadata())
	}

	if resource.HasChild("bypass") {
		bypassAttr := resource.GetAttribute("bypass")
		bypass = bypassAttr.AsStringValues()
	}

	return storage.NetworkRule{
		Metadata:       resource.GetMetadata(),
		Bypass:         bypass,
		AllowByDefault: allowByDefault,
	}
}
