
Define user session termination duration

```hcl
resource "aws_ssoadmin_permission_set" "example" {
  name             = "Example"
  description      = "An example"
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssoadmin_permission_set#session_duration
