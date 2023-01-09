# METADATA
# title :"IAM Policies Present"
# description: "Ensure that required policies are present in all IAM roles."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: iam-policies-present 
#   recommended_action: "Modify IAM roles to attach required policies"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            iam_required_policy_names: settings.iam_required_policy_names || this.settings.iam_required_policy_names.default
#        };
#
#        if (!config.iam_required_policy_names.length) return callback(null, results, source);
#
#        config.iam_required_policy_names = config.iam_required_policy_names.split(',');
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
#            if (!role.RoleName) return cb();
#
#            // Get managed policies attached to role
#            var listAttachedRolePolicies = helpers.addSource(cache, source,
#                ['iam', 'listAttachedRolePolicies', region, role.RoleName]);
#
#            // Get inline policies attached to role
#            var listRolePolicies = helpers.addSource(cache, source,
#                ['iam', 'listRolePolicies', region, role.RoleName]);
#
#            if (!listAttachedRolePolicies || listAttachedRolePolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM attached policy for role: ' + role.RoleName + ': ' + helpers.addError(listAttachedRolePolicies), region, role.Arn);
#                return cb();
#            }
#
#            if (!listRolePolicies || listRolePolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), region, role.Arn);
#                return cb();
#            }
#
#            var attachedPolicies = [];
#            var difference = [];
#
#            // See if role has admin managed policy
#            if (listAttachedRolePolicies.data &&
#                listAttachedRolePolicies.data.AttachedPolicies) {
#
#                for (let policy of listAttachedRolePolicies.data.AttachedPolicies) {
#                    attachedPolicies.push(policy.PolicyName);
#                }
#            }
#
#            if (listRolePolicies.data && listRolePolicies.data.PolicyNames) attachedPolicies = attachedPolicies.concat(listRolePolicies.data.PolicyNames);
#
#            for (let policy of config.iam_required_policy_names) {
#                if (!attachedPolicies.includes(policy)) difference.push(policy);
#            }
#
#            if (difference.length) {
#                helpers.addResult(results, 2,
#                    `IAM role does not have these required policies attached: ${difference.join(', ')}`, region, role.Arn);
#            } else {
#                helpers.addResult(results, 0,
#                    'IAM role has all required policies attached', region, role.Arn);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }