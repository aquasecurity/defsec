package computing

var terraformNoCommonPrivateInstanceGoodExamples = []string{
	`
 resource "nifcloud_instance" "good_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = nifcloud_private_lan.main.id
   }
 }
 `,
}

var terraformNoCommonPrivateInstanceBadExamples = []string{
	`
 resource "nifcloud_instance" "bad_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_PRIVATE"
   }
 }
 `,
}

var terraformNoCommonPrivateInstanceLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#network_id`,
}

var terraformNoCommonPrivateInstanceRemediationMarkdown = ``
