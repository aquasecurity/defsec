
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
```hcl
resource "google_sql_database_instance" "new_instance_sql_replica" {
  name                 = "replica"
  region               = "europe-west3"
  database_version     = "POSTGRES_14"
  master_instance_name = google_sql_database_instance.instance[0].name
  deletion_protection  = terraform.workspace == "prod" ? true : false

  replica_configuration {
    connect_retry_interval  = 0
    failover_target         = false
    master_heartbeat_period = 0
  }
}

```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true

