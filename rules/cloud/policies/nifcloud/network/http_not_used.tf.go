package network

var terraformHttpNotUsedGoodExamples = []string{
	`
 resource "nifcloud_elb" "good_example" {
     protocol = "HTTPS"
 }
 `,
	`
resource "nifcloud_load_balancer" "good_example" {
    load_balancer_port = 443
}
`,
}

var terraformHttpNotUsedBadExamples = []string{
	`
 resource "nifcloud_elb" "bad_example" {
     protocol = "HTTP"

     network_interface {
         network_id     = "net-COMMON_GLOBAL"
         is_vip_network = true
     }
 }
 `,
	`
resource "nifcloud_load_balancer" "bad_example" {
    load_balancer_port = 80
}
`,
}

var terraformHttpNotUsedLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol`,
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port`,
}

var terraformHttpNotUsedRemediationMarkdown = ``
