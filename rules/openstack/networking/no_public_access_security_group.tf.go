package networking

var terraformNoPublicAccessSGGoodExamples = []string{
	`
resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  security_group_id = openstack_networking_secgroup_v2.ssh.id
  remote_ip_prefix  = "10.0.1.1/24"
}
 			`,
}

var terraformNoPublicAccessSGBadExamples = []string{
	`
resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  security_group_id = openstack_networking_secgroup_v2.ssh.id
  remote_ip_prefix  = "0.0.0.0/0"
}
 			`,
}

var terraformNoPublicAccessSGLinks = []string{
	`https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2`,
}

var terraformNoPublicAccessSGRemediationMarkdown = ``
