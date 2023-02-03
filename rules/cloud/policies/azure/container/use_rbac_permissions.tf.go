package container

var terraformUseRbacPermissionsGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
	// azurerm < 2.99.0
	role_based_access_control {
 		enabled = true
 	}

	// azurerm >= 2.99.0
 	role_based_access_control_enabled = true
 }
 `, `
resource "azurerm_kubernetes_cluster" "aks_cluster" {
  name                            = var.name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  dns_prefix                      = var.name
  kubernetes_version              = var.cluster_version
  api_server_authorized_ip_ranges = var.ip_whitelist
  azure_policy_enabled            = true
  default_node_pool {
    name                = "default"
    enable_auto_scaling = true
    min_count           = var.node_min_count
    max_count           = var.node_max_count
    max_pods            = var.pod_max_count # If you don't specify only allows 30 pods
    vm_size             = var.vm_size
    os_disk_size_gb     = 250 # default 30GB
    vnet_subnet_id      = var.vnet_subnet_id
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  identity {
    type = "SystemAssigned"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = [data.azuread_group.aks_admins.object_id]
  }

}
`,
}

var terraformUseRbacPermissionsBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
	// azurerm < 2.99.0
 	role_based_access_control {
 		enabled = false
 	}

	// azurerm >= 2.99.0
	role_based_access_control_enabled = false
 }
 `,
}

var terraformUseRbacPermissionsLinks = []string{
	`https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control`,
}

var terraformUseRbacPermissionsRemediationMarkdown = ``
