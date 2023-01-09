# METADATA
# title :"Empty Groups"
# description: "Ensures all groups have at least one member"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: empty-groups 
#   recommended_action: "Remove unused groups without users"
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
#            var getGroup = helpers.addSource(cache, source,
#                ['iam', 'getGroup', region, group.GroupName]);
#
#            if (!getGroup || getGroup.err || !getGroup.data) {
#                helpers.addResult(results, 3, 'Unable to query for group: ' + group.GroupName + ': ' + helpers.addError(getGroup), 'global', group.Arn);
#            } else if (!getGroup.data.Users) {
#                helpers.addResult(results, 3, 'Unable to query for group: ' + group.GroupName + ': No users returned attached', 'global', group.Arn);
#            } else if (!getGroup.data.Users.length) {
#                helpers.addResult(results, 1, 'Group: ' + group.GroupName + ' does not contain any users', 'global', group.Arn);
#                return cb();
#            } else {
#                helpers.addResult(results, 0, 'Group: ' + group.GroupName + ' contains ' + getGroup.data.Users.length + ' user(s)', 'global', group.Arn);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }