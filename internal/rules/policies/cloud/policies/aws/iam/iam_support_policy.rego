# METADATA
# title :"IAM Support Policy"
# description: "Ensures that an IAM role, group or user exists with specific permissions to access support center."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-support-policy 
#   recommended_action: "Ensure that an IAM role has permission to access support center."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        const listPolicies = helpers.addSource(cache, source,
#            ['iam', 'listPolicies', region]);
#
#        if (!listPolicies) return callback(null, results, source);
#
#        if (listPolicies.err || !listPolicies.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for IAM policies: ' + helpers.addError(listPolicies));
#            return callback(null, results, source);
#        }
#
#        if (!listPolicies.data.length) {
#            helpers.addResult(results, 0,
#                'No IAM policies found');
#            return callback(null, results, source);
#        }
#
#        var found = listPolicies.data.find(policy => policy.PolicyName == 'AWSSupportAccess');
#
#        if (found) {
#            helpers.addResult(results, 0,
#                'AWSSupportAccess policy is attached to a user, role or group', 'global', found.Arn);
#        } else {
#            helpers.addResult(results, 2,
#                'No role, user or group attached to the AWSSupportAccess policy', 'global');
#        }
#
#        callback(null, results, source);
#    }