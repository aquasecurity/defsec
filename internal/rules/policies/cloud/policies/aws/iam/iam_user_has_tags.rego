# METADATA
# title :"IAM User Has Tags"
# description: "Ensure that AWS IAM Users have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags_users.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-user-has-tags 
#   recommended_action: "Modify IAM User and add tags"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var listUsers = helpers.addSource(cache, source,
#            ['iam', 'listUsers', region]);
#
#        if (!listUsers) return callback(null, results, source);
#    
#        if (listUsers.err || !listUsers.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for iam users: ' + helpers.addError(listUsers));
#            return callback(null, results, source);
#        }
#    
#        if (!listUsers.data.length) {
#            helpers.addResult(results, 0, 'No iam users found', 'global');
#        } 
#
#        for (var user of listUsers.data) {
#            if (!user.UserName) continue;
#
#            var getUser = helpers.addSource(cache, source,
#                ['iam', 'getUser', region, user.UserName]);
#
#            if (!getUser || getUser.err || !getUser.data || !getUser.data.User) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM user details: ' + user.UserName + ': ' + helpers.addError(getUser), 'global', user.Arn);
#                continue;
#            }
#            
#            if (!getUser.data.User.Tags || !getUser.data.User.Tags.length) {
#                helpers.addResult(results, 2, 'IAM User does not have tags', 'global', user.Arn);
#            } else {
#                helpers.addResult(results, 0, 'IAM User has tags', 'global', user.Arn);
#            }
#            
#        }
#
#        return callback(null, results, source);
#    }