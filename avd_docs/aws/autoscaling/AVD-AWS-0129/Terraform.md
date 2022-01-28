
Remove sensitive data from the EC2 instance user-data

```hcl
resource "aws_iam_instance_profile" "good_example" {
  // ...
}

resource "aws_launch_template" "good_example" {
  image_id           = "ami-12345667"
  instance_type = "t2.small"
  
  iam_instance_profile {
    name = aws_iam_instance_profile.good_profile.arn
  }
  
  user_data = <<EOF
  export GREETING=hello
EOF
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data
        