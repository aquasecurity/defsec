---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance"
---

Enable checkpoints logging.

```hcl
resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_checkpoints"
 			value = "on"
 		}
 	}
 }
```
