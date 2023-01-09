# METADATA
# title :"Root Account In Use"
# description: "Ensures the root account is not being actively used"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: root-account-in-use 
#   recommended_action: "Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the root account, and store its password and token generation QR codes in a secure place."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        this._run(cache, settings, callback, new Date());
#    }