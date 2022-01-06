---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance"
---

Remove public access from database instances

```hcl
resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 		}
 	}
 }
```
