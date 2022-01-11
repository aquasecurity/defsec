
Remove plaintext secrets and encrypt them within a secrets manager instead.

```hcl
variable "password" {
  description = "The root password for our VM"
  type        = string
}

resource "evil_corp" "virtual_machine" {
  root_password = var.password
}
```

#### Remediation Links
 - https://www.terraform.io/docs/state/sensitive-data.html
        