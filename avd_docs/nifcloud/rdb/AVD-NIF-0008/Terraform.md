
Set the database to not be publicly accessible

```hcl
 resource "nifcloud_db_instance" "good_example" {
 	publicly_accessible = false
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible

