# METADATA
# title :"Group Inline Policies"
# description: "Ensures that groups do not have any inline policies"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: group-inline-policies 
#   recommended_action: "Remove inline policies attached to groups"
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
#        var listGroups = helpers.addSource(cache, source,
#            ['iam', 'listGroups', region]);
#
#        if (!listGroups) return callback(null, results, source);
#
#        if (listGroups.err || !listGroups.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for groups: ' + helpers.addError(listGroups));
#            return callback(null, results, source);
#        }
#
#        if (!listGroups.data.length) {
#            helpers.addResult(results, 0, 'No groups found');
#            return callback(null, results, source);
#        }
#
#        async.each(listGroups.data, function(group, cb){
#            if (!group.GroupName) return cb();
#
#            var listGroupPolicies = helpers.addSource(cache, source,
#                ['iam', 'listGroupPolicies', region, group.GroupName]);
#
#            if (!listGroupPolicies || listGroupPolicies.err || !listGroupPolicies.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query inline policies for group: ' + group.GroupName + ': ' + helpers.addError(listGroupPolicies),
#                    'global', group.Arn);
#                return cb();
#            }
#            
#            if (!listGroupPolicies.data.PolicyNames || !listGroupPolicies.data.PolicyNames.length) {
#                helpers.addResult(results, 0,
#                    'Group: ' + group.GroupName + ' does not contain any inline policy',
#                    'global', group.Arn);
#            } else {
#                helpers.addResult(results, 2,
#                    'Group: ' + group.GroupName + ' contains ' + listGroupPolicies.data.PolicyNames.length + ' inline policy(s)',
#                    'global', group.Arn);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }