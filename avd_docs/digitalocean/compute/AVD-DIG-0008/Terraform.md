
Set maintenance policy deterministically when auto upgrades are enabled

```hcl
resource "digitalocean_kubernetes_cluster" "foo" {
	name    	 = "foo"
	region  	 = "nyc1"
	version 	 = "1.20.2-do.0"
	auto_upgrade = true

	node_pool {
		name       = "autoscale-worker-pool"
		size       = "s-2vcpu-2gb"
		auto_scale = true
		min_nodes  = 1
		max_nodes  = 5
	}
}

```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#auto-upgrade-example

