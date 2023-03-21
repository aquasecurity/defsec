package network

var terraformNoPublicIngressGoodExamples = []string{
	`
 resource "azurerm_network_security_rule" "good_example" {
 	direction = "Inbound"
 	destination_address_prefix = "10.0.0.0/16"
 	access = "Allow"
 }`, `
resource "azurerm_network_security_rule" "allow_lb_prober" {
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp" # Probes are always TCP
  source_port_range                          = "*"
  destination_port_ranges                    = "443"
  source_address_prefix                      = "168.63.129.16" // single public IP (Azure well known)
}`,
}

var terraformNoPublicIngressBadExamples = []string{
	`
 resource "azurerm_network_security_rule" "bad_example" {
 	direction = "Inbound"
 	source_address_prefix = "0.0.0.0/0"
 	access = "Allow"
 }`,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule`,
}

var terraformNoPublicIngressRemediationMarkdown = ``
