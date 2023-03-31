package network

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "nifcloud_load_balancer" "good_example" {
    load_balancer_port  = 443
    policy_type         = "standard"
    ssl_policy_name     = "Standard Ciphers D ver1"
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "nifcloud_load_balancer" "bad_example" {
    load_balancer_port  = 443
    policy_type         = "standard"
    ssl_policy_name     = ""
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_name`,
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer_listener#ssl_policy_name`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
