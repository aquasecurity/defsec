
Don't use sensitive data in user data

```hcl
 resource "aws_launch_configuration" "as_conf" {
   name          = "web_config"
   image_id      = data.aws_ami.ubuntu.id
   instance_type = "t2.micro"
   user_data     = <<EOF
 export GREETING="Hello there"
 EOF
 }
 
```
```hcl
 resource "aws_launch_configuration" "as_conf" {
 	name             = "web_config"
 	image_id         = data.aws_ami.ubuntu.id
 	instance_type    = "t2.micro"
 	user_data_base64 = "ZXhwb3J0IEVESVRPUj12aW1hY3M="
   }
   
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64

