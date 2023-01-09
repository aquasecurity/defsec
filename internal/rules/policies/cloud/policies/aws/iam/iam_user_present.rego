# METADATA
# title :"IAM User Present"
# description: "Ensure that at least one IAM user exists so that access to your AWS services and resources is made only through IAM users instead of the root account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-user-present 
#   recommended_action: "Create IAM user(s) and use them to access AWS services and resources."
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
#        var listUsers = helpers.addSource(cache, source,
#            ['iam', 'listUsers', region]);
#
#        if (!listUsers) return callback(null, results, source);
#    
#        if (listUsers.err || !listUsers.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for users: ' + helpers.addError(listUsers));
#            return callback(null, results, source);
#        }
#    
#        if (!listUsers.data.length) {
#            helpers.addResult(results, 2, 'No users found', 'global');
#        } else {
#            helpers.addResult(results, 0, `Found ${listUsers.data.length} users`, 'global');
#        }
#
#        return callback(null, results, source);
#    }