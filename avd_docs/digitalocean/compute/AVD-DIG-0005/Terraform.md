
Enable surge upgrades for a faster and more reliable upgrade of your Kubernetes cluster.

```hcl
data "digitalocean_kubernetes_versions" "example" {
  version_prefix = "1.22."
}
resource "digitalocean_kubernetes_cluster" "foo" {
  name          = "foo"
  region        = "nyc1"
  surge_upgrade = true
  version       = data.digitalocean_kubernetes_versions.example.latest_version

  node_pool {
    name       = "default"
    size       = "s-1vcpu-2gb"
    node_count = 3
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade
