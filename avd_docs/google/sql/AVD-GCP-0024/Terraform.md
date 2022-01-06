---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true"
---

Enable automated backups

```hcl
resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = true
 		}
 	}
 }
```
