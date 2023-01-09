# METADATA
# title :"IAM Role Last Used"
# description: "Ensures IAM roles that have not been used within the given time frame are deleted."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/about-aws/whats-new/2019/11/identify-unused-iam-roles-easily-and-remove-them-confidently-by-using-the-last-used-timestamp/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-role-last-used 
#   recommended_action: "Delete IAM roles that have not been used within the expected time frame."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            iam_role_last_used_fail: settings.iam_role_last_used_fail || this.settings.iam_role_last_used_fail.default,
#            iam_role_last_used_warn: settings.iam_role_last_used_warn || this.settings.iam_role_last_used_warn.default,
#            iam_role_ignore_path: settings.iam_role_ignore_path || this.settings.iam_role_ignore_path.default,
#            skip_aws_service_roles: settings.skip_aws_service_roles || this.settings.skip_aws_service_roles.default,
#            iam_role_policies_ignore_tag: settings.iam_role_policies_ignore_tag || this.settings.iam_role_policies_ignore_tag.default
#        };
#
#        config.skip_aws_service_roles = (config.skip_aws_service_roles == 'true');
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        
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
#        async.each(listRoles.data, function(role, cb){
#            if (!role.RoleName || (config.skip_aws_service_roles && role.Path && role.Path.startsWith('/aws-service-role/'))) return cb();
#
#            // Skip roles with user-defined paths
#            if (config.iam_role_ignore_path &&
#                config.iam_role_ignore_path.length &&
#                role.Path &&
#                role.Path.indexOf(config.iam_role_ignore_path) > -1) {
#                return cb();
#            }
#
#            // Get role details
#            var getRole = helpers.addSource(cache, source,
#                ['iam', 'getRole', region, role.RoleName]);
#
#            if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM role details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
#                return cb();
#            }
#
#            //Skip roles with user defined tags
#            if (config.iam_role_policies_ignore_tag && config.iam_role_policies_ignore_tag.length) {
#                if (config.iam_role_policies_ignore_tag.split(':').length == 2){
#                    var key = config.iam_role_policies_ignore_tag.split(':')[0].trim();
#                    var value= new RegExp(config.iam_role_policies_ignore_tag.split(':')[1].trim());
#                    if (getRole.data.Role.Tags && getRole.data.Role.Tags.length){
#                        if (getRole.data.Role.Tags.find(tag =>
#                            tag.Key == key && value.test(tag.Value))) return cb();
#                    }
#                }
#            }
#
#            if (!getRole.data.Role.RoleLastUsed ||
#                !getRole.data.Role.RoleLastUsed.LastUsedDate) {
#                helpers.addResult(results, 2,
#                    'IAM role: ' + role.RoleName + ' has not been used', 'global', role.Arn);
#                return cb();
#            }
#
#            var daysAgo = helpers.daysAgo(getRole.data.Role.RoleLastUsed.LastUsedDate);
#
#            var returnCode = 0;
#            var returnMsg = `IAM role was last used ${daysAgo} days ago in the ${getRole.data.Role.RoleLastUsed.Region || 'unknown'} region`;
#            if (daysAgo > config.iam_role_last_used_fail) {
#                returnCode = 2;
#            } else if (daysAgo > config.iam_role_last_used_warn) {
#                returnCode = 1;
#            }
#
#            helpers.addResult(results, returnCode, returnMsg, 'global', role.Arn, custom);
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }