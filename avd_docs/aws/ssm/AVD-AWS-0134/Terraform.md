
Remove this potential exfiltration HTTP request.

```hcl
resource "aws_ssm_parameter" "db_password" {
  name = "db_password"
  type = "SecureString"
  value = var.db_password
}

 
```


