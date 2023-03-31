package compute

var terraformNoPublicIngressGoodExamples = []string{
	`
resource "google_compute_firewall" "good_example" {
  source_ranges = ["1.2.3.4/32"]
  allow {
    protocol = "icmp"
  }
}`,
	`
resource "google_compute_firewall" "allow-vms-to-some-machine" {
  name      = "allow-vms-to-some-machine"
  network   = local.network
  priority  = 1300
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["8081"]
  }
  source_tags = ["vms"]
  target_tags = ["some-machine"]
}`,
	`
resource "google_compute_firewall" "test" {
  name    = "gmp-validating-webhook-fw"
  network = google_compute_network.my_vpc_name.self_link

  allow {
    protocol = "tcp"
    ports    = ["8443"]
  }

  target_tags   = [ "k8s-node-pool" ]
  source_ranges = [google_container_cluster.my_cluster_name.private_cluster_config[0].master_ipv4_cidr_block]
}
`,
}

var terraformNoPublicIngressBadExamples = []string{
	`
resource "google_compute_firewall" "bad_example" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "icmp"
  }
}`,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges`,
	`https://www.terraform.io/docs/providers/google/r/compute_firewall.html`,
}

var terraformNoPublicIngressRemediationMarkdown = ``
