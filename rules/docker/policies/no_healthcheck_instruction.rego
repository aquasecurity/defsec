# METADATA
# title: "No HEALTHCHECK defined"
# description: "You should add HEALTHCHECK instruction in your docker container images to perform the health check on running containers."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://blog.aquasec.com/docker-security-best-practices
# custom:
#   id: DS026
#   avd_id: AVD-DS-0026
#   severity: LOW
#   short_code: no-healthcheck
#   recommended_action: "Add HEALTHCHECK instruction in Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS026

import data.lib.docker

deny[res] {
	count(docker.healthcheck) == 0
	msg := "Add HEALTHCHECK instruction in your Dockerfile"
	res := result.new(msg, {})
}
