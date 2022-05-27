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
