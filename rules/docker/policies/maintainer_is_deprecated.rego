# METADATA
# title: "Deprecated MAINTAINER used"
# description: "MAINTAINER has been deprecated since Docker 1.13.0."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/engine/deprecated/#maintainer-in-dockerfile
# custom:
#   id: DS022
#   avd_id: AVD-DS-0022
#   severity: HIGH
#   short_code: no-maintainer
#   recommended_action: "Use LABEL instead of MAINTAINER"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS022

import data.lib.docker

get_maintainer[mntnr] {
	mntnr := input.Stages[_].Commands[_]
	mntnr.Cmd == "maintainer"
}

deny[res] {
	mntnr := get_maintainer[_]
	msg := sprintf("MAINTAINER should not be used: 'MAINTAINER %s'", [mntnr.Value[0]])
	res := result.new(msg, mntnr)
}
