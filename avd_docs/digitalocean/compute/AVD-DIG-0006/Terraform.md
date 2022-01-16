Set `auto_upgrade` to `true` and set `maintenance_policy` to a time window when you know the workloads of your cluster is not peaking.

```hcl
data "digitalocean_kubernetes_versions" "example" {
  version_prefix = "1.22."
}

resource "digitalocean_kubernetes_cluster" "foo" {
  name         = "foo"
  region       = "nyc1"
  auto_upgrade = true
  version      = data.digitalocean_kubernetes_versions.example.latest_version

  # remember to actively set this
  maintenance_policy {
    start_time  = "04:00"
    day         = "sunday"
  }

  node_pool {
    name       = "default"
    size       = "s-1vcpu-2gb"
    node_count = 3
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#auto_upgrade
