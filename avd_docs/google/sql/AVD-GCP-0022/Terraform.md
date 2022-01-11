
Enable disconnection logging.

```hcl
resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_12"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
        