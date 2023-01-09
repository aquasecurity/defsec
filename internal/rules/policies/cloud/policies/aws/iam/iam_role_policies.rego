# METADATA
# title :"IAM Role Policies"
# description: "Ensures IAM role policies are properly scoped with specific permissions"
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
#   short_code: iam-role-policies 
#   recommended_action: "Ensure that all IAM roles are scoped to specific services and API calls."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            iam_role_policies_ignore_path: settings.iam_role_policies_ignore_path || this.settings.iam_role_policies_ignore_path.default,
#            ignore_service_specific_wildcards: settings.ignore_service_specific_wildcards || this.settings.ignore_service_specific_wildcards.default,
#            ignore_identity_federation_roles: settings.ignore_identity_federation_roles || this.settings.ignore_identity_federation_roles.default,
#            ignore_aws_managed_iam_policies: settings.ignore_aws_managed_iam_policies || this.settings.ignore_aws_managed_iam_policies.default,
#            ignore_customer_managed_iam_policies: settings.ignore_customer_managed_iam_policies || this.settings.ignore_customer_managed_iam_policies.default,
#            iam_role_policies_ignore_tag: settings.iam_role_policies_ignore_tag || this.settings.iam_role_policies_ignore_tag.default
#        };
#
#        config.ignore_service_specific_wildcards = (config.ignore_service_specific_wildcards === 'true');
#        config.ignore_identity_federation_roles = (config.ignore_identity_federation_roles === 'true');
#        config.ignore_aws_managed_iam_policies = (config.ignore_aws_managed_iam_policies === 'true');
#        config.ignore_customer_managed_iam_policies = (config.ignore_customer_managed_iam_policies === 'true');
#
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
#            if (!role.RoleName) return cb();
#
#            // Skip roles with user-defined paths
#            if (config.iam_role_policies_ignore_path &&
#                config.iam_role_policies_ignore_path.length &&
#                role.Path &&
#                role.Path.indexOf(config.iam_role_policies_ignore_path) > -1) {
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
#            if (config.ignore_identity_federation_roles &&
#                helpers.hasFederatedUserRole(helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument))) {
#                helpers.addResult(results, 0,
#                    'Role is federated user role',
#                    'global', role.Arn, custom);
#                return cb();
#            }
#
#            // Get managed policies attached to role
#            var listAttachedRolePolicies = helpers.addSource(cache, source,
#                ['iam', 'listAttachedRolePolicies', region, role.RoleName]);
#
#            // Get inline policies attached to role
#            var listRolePolicies = helpers.addSource(cache, source,
#                ['iam', 'listRolePolicies', region, role.RoleName]);
#
#            var getRolePolicy = helpers.addSource(cache, source,
#                ['iam', 'getRolePolicy', region, role.RoleName]);
#
#            if (!listAttachedRolePolicies || listAttachedRolePolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM attached policy for role: ' + role.RoleName + ': ' + helpers.addError(listAttachedRolePolicies), 'global', role.Arn);
#                return cb();
#            }
#
#            if (!listRolePolicies || listRolePolicies.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), 'global', role.Arn);
#                return cb();
#            }
#
#            var roleFailures = [];
#
#            // See if role has admin managed policy
#            if (listAttachedRolePolicies.data &&
#                listAttachedRolePolicies.data.AttachedPolicies) {
#
#                for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
#                    if (policy.PolicyArn === managedAdminPolicy) {
#                        roleFailures.push('Role has managed AdministratorAccess policy');
#                        break;
#                    }
#
#                    if (config.ignore_aws_managed_iam_policies && /^arn:aws:iam::aws:.*/.test(policy.PolicyArn)) continue;
#
#                    if (config.ignore_customer_managed_iam_policies && /^arn:aws:iam::[0-9]{12}:.*/.test(policy.PolicyArn)) continue;
#
#                    var getPolicy = helpers.addSource(cache, source,
#                        ['iam', 'getPolicy', region, policy.PolicyArn]);
#
#                    if (getPolicy &&
#                        getPolicy.data &&
#                        getPolicy.data.Policy &&
#                        getPolicy.data.Policy.DefaultVersionId) {
#                        var getPolicyVersion = helpers.addSource(cache, source,
#                            ['iam', 'getPolicyVersion', region, policy.PolicyArn]);
#
#                        if (getPolicyVersion &&
#                            getPolicyVersion.data &&
#                            getPolicyVersion.data.PolicyVersion &&
#                            getPolicyVersion.data.PolicyVersion.Document) {
#                            let statements = helpers.normalizePolicyDocument(
#                                getPolicyVersion.data.PolicyVersion.Document);
#                            if (!statements) break;
#
#                            addRoleFailures(roleFailures, statements, 'managed', config.ignore_service_specific_wildcards);
#                        }
#                    }
#                }
#            }
#
#            if (listRolePolicies.data &&
#                listRolePolicies.data.PolicyNames) {
#
#                for (var p in listRolePolicies.data.PolicyNames) {
#                    var policyName = listRolePolicies.data.PolicyNames[p];
#
#                    if (getRolePolicy &&
#                        getRolePolicy[policyName] &&
#                        getRolePolicy[policyName].data &&
#                        getRolePolicy[policyName].data.PolicyDocument) {
#                        var statements = helpers.normalizePolicyDocument(
#                            getRolePolicy[policyName].data.PolicyDocument);
#                        if (!statements) break;
#                        addRoleFailures(roleFailures, statements, 'inline', config.ignore_service_specific_wildcards);
#                    }
#                }
#            }
#
#            if (roleFailures.length) {
#                helpers.addResult(results, 2,
#                    roleFailures.join(', '),
#                    'global', role.Arn, custom);
#            } else {
#                helpers.addResult(results, 0,
#                    'Role does not have overly-permissive policy',
#                    'global', role.Arn, custom);
#            }
#
#            cb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }