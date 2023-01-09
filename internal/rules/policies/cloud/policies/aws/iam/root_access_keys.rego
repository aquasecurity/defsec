# METADATA
# title :"Root Access Keys"
# description: "Ensures the root account is not using access keys"
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
#   short_code: root-access-keys 
#   recommended_action: "Remove access keys for the root account and setup IAM users with limited permissions instead"
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
#                if (!obj.access_key_1_active &&
#                    !obj.access_key_2_active) {
#                    helpers.addResult(results, 0, 'Access keys were not found for the root account', 'global', obj.arn);
#                } else {
#                    helpers.addResult(results, 2, 'Access keys were found for the root account', 'global', obj.arn);
#                }
#
#                break;
#            }
#        }
#
#        if (!found) {
#            helpers.addResult(results, 3, 'Unable to query for root user');
#        }
#
#        callback(null, results, source);
#    }