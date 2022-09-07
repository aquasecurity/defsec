
Enable surge upgrades in your Kubernetes cluster

```hcl
resource "digitalocean_kubernetes_cluster" "surge_upgrade_good" {
	name   = "foo"
	region = "nyc1"
	version = "1.20.2-do.0"
	surge_upgrade = true

	node_pool {
		name       = "worker-pool"
		size       = "s-2vcpu-2gb"
		node_count = 3
	
		taint {
			key    = "workloadKind"
			value  = "database"
			effect = "NoSchedule"
		}
	}
}
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade

