
Disable cross database ownership chaining

```hcl
resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "SQLSERVER_2017_STANDARD"
  region           = "us-central1"
  settings {
    database_flags {
      name  = "cross db ownership chaining"
      value = "off"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
        