# METADATA
# title: "Image tag \":latest\" used"
# description: "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/configuration/overview/#container-images
# custom:
#   id: KSV013
#   avd_id: AVD-KSV-0013
#   severity: MEDIUM
#   short_code: use-specific-tags
#   recommended_action: "Use a specific container image tag that is not 'latest'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV013

import data.lib.kubernetes

default checkUsingLatestTag = false

# getTaggedContainers returns the names of all containers which
# have tagged images.
getTaggedContainers[container] {
	# If the image defines a digest value, we don't care about the tag
	container := kubernetes.containers[_]
	digest := split(container.image, "@")[1]
}

getTaggedContainers[container] {
	# No digest, look at tag
	container := kubernetes.containers[_]
	tag := split(container.image, ":")[1]
	tag != "latest"
}

# getUntaggedContainers returns the names of all containers which
# have untagged images or images with the latest tag.
getUntaggedContainers[container] {
	container := kubernetes.containers[_]
	not getTaggedContainers[container]
}

deny[res] {
	output := getUntaggedContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should specify an image tag", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
