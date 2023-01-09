# METADATA
# title :"Root MFA Enabled"
# description: "Ensures a multi-factor authentication device is enabled for the root account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: root-mfa-enabled 
#   recommended_action: "Enable an MFA device for the root account and then use an IAM user for managing services"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var generateCredentialReport = helpers.addSource(cache, source,
#            ['iam', 'generateCredentialReport', region]);
#
#        if (!generateCredentialReport) return callback(null, results, source);
#
#        if (generateCredentialReport.err || !generateCredentialReport.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for root user: ' + helpers.addError(generateCredentialReport));
#            return callback(null, results, source);
#        }
#
#        var found = false;
#
#        for (var r in generateCredentialReport.data) {
#            var obj = generateCredentialReport.data[r];
#
#            if (obj && obj.user === '<root_account>') {
#                found = true;
#
#                if (obj.mfa_active) {
#                    helpers.addResult(results, 0,
#                        'An MFA device was found for the root account', 'global', obj.arn);
#                } else {
#                    helpers.addResult(results, 2,
#                        'An MFA device was not found for the root account', 'global', obj.arn);
#                }
#
#                break;
#            }
#        }
#
#        if (settings.govcloud && !found) {
#            helpers.addResult(results, 0, 'Root MFA is not required for AWS GovCloud');
#        } else if (!found) {
#            helpers.addResult(results, 3, 'Unable to query for root user');
#        }
#
#        callback(null, results, source);
#    }