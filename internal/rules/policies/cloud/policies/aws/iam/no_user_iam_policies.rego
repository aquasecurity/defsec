# METADATA
# title :"No User IAM Policies"
# description: "Ensures IAM policies are not connected directly to IAM users"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: no-user-iam-policies 
#   recommended_action: "Create groups with the required policies, move the IAM users to the applicable groups, and then remove the inline and directly attached policies from the IAM user."
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
#                'Unable to query for user IAM policy status: ' + helpers.addError(listUsers));
#            return callback(null, results, source);
#        }
#
#        if (!listUsers.data.length) {
#            helpers.addResult(results, 0, 'No user accounts found');
#            return callback(null, results, source);
#        }
#
#        async.each(listUsers.data, function(user, cb){
#            if (!user.UserName) return cb();
#
#            var listAttachedUserPolicies = helpers.addSource(cache, source,
#                ['iam', 'listAttachedUserPolicies', region, user.UserName]);
#
#            var listUserPolicies = helpers.addSource(cache, source,
#                ['iam', 'listUserPolicies', region, user.UserName]);
#
#            if (!listAttachedUserPolicies) return cb();
#            if (!listUserPolicies) return cb();
#
#            if (listAttachedUserPolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
#                return cb();
#            }
#
#            if (listUserPolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM user policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
#                return cb();
#            }
#
#            if (!listAttachedUserPolicies.data || !listUserPolicies.data) {
#                helpers.addResult(results, 3, 'Unable to query policies for user: ' +
#                    user.UserName + ': no data returned', 'global', user.Arn);
#                return cb();
#            }
#
#            if ((listAttachedUserPolicies.data.AttachedPolicies &&
#                listAttachedUserPolicies.data.AttachedPolicies.length) ||
#               (listUserPolicies.data.PolicyNames &&
#                listUserPolicies.data.PolicyNames.length)) {
#                helpers.addResult(results, 1, 'User is using attached or inline policies', 'global', user.Arn);
#            } else {
#                helpers.addResult(results, 0, 'User is not using attached or inline policies', 'global', user.Arn);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }