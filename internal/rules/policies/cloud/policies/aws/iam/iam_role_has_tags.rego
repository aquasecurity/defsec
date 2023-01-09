# METADATA
# title :"IAM Role Has Tags"
# description: "Ensure that AWS IAM Roles have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-role-has-tags 
#   recommended_action: "Modify Roles to add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var listRoles = helpers.addSource(cache, source,
#            ['iam', 'listRoles', region]);
#
#        if (!listRoles) return callback(null, results, source);
#
#        if (listRoles.err || !listRoles.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
#            return callback(null, results, source);
#        }
#
#        if (!listRoles.data.length) {
#            helpers.addResult(results, 0, 'No IAM roles found');
#            return callback(null, results, source);
#        }
#        
#        for (var role of listRoles.data) {
#            if (!role.RoleName) continue;
#
#            var getRole = helpers.addSource(cache, source,
#                ['iam', 'getRole', region, role.RoleName]);
#              
#            if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM role details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
#                continue;
#            }
#            
#            if (!getRole.data.Role.Tags || !getRole.data.Role.Tags.length) {
#                helpers.addResult(results, 2, 'IAM Role does not have tags', 'global', role.Arn);
#            } else {
#                helpers.addResult(results, 0, 'IAM Role has tags', 'global', role.Arn);
#            } 
#
#        }
#        
#        return callback(null, results, source);
#    }