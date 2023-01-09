# METADATA
# title :"Trusted Cross Account Roles"
# description: "Ensures that only trusted cross-account IAM roles can be used."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: trusted-cross-account-roles 
#   recommended_action: "Delete the IAM roles that are associated with untrusted account IDs."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config= {
#            whitelisted_aws_account_principals : settings.whitelisted_aws_account_principals || this.settings.whitelisted_aws_account_principals.default,
#            whitelisted_aws_account_principals_regex : settings.whitelisted_aws_account_principals_regex || this.settings.whitelisted_aws_account_principals_regex.default,
#            iam_whitelist_aws_organization_accounts: settings.iam_whitelist_aws_organization_accounts || this.settings.iam_whitelist_aws_organization_accounts.default
#        };
#        var makeRegexBased = (config.whitelisted_aws_account_principals_regex.length) ? true : false;
#        var whitelistOrganization = (config.iam_whitelist_aws_organization_accounts == 'true'); 
#        config.whitelisted_aws_account_principals_regex = new RegExp(config.whitelisted_aws_account_principals_regex);
#        var results = [];
#        var source = {};
#        
#        var region = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);
#
#        var listRoles = helpers.addSource(cache, source,
#            ['iam', 'listRoles', region]);
#
#        if (!listRoles) return callback(null, results, source);
#
#        if (listRoles.err || !listRoles.data) {
#            helpers.addResult(results, 3,
#                `Unable to query for IAM roles: ${helpers.addError(listRoles)}`);
#            return callback(null, results, source);
#        }
#
#        if (!listRoles.data.length) {
#            helpers.addResult(results, 0, 'No IAM roles found');
#            return callback(null, results, source);
#        }
#
#        let organizationAccounts = [];
#        if (whitelistOrganization) {
#            var listAccounts = helpers.addSource(cache, source,
#                ['organizations', 'listAccounts', region]);
#    
#            if (!listAccounts || listAccounts.err || !listAccounts.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, region);
#                return callback(null, results, source);
#            }
#
#            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
#        }
#
#        listRoles.data.forEach(role => {
#            if (!role.Arn || !role.AssumeRolePolicyDocument) return;
#
#            var statements = helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument);
#
#            if (!statements || !statements.length) {
#                helpers.addResult(results, 0,
#                    'IAM role does not contain trust relationship statements',
#                    'global', role.Arn);
#            }
#
#            var restrictedAccountPrincipals = [];
#            var crossAccountRole = false;
#
#            for (var statement of statements) {
#                if (!statement.Effect || statement.Effect !== 'Allow') continue;
#
#                if (statement.Principal && helpers.crossAccountPrincipal(statement.Principal, accountId)) {
#                    crossAccountRole = true;
#                    var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
#                    if (principals.length) {
#                        principals.forEach(principal => {
#                            if (whitelistOrganization) {
#                                if (organizationAccounts.find(account => principal.includes(account))) return;
#                            }
#                            if (makeRegexBased) {
#                                if (!config.whitelisted_aws_account_principals_regex.test(principal) &&
#                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                            } else if (!config.whitelisted_aws_account_principals.includes(principal) &&
#                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                        });
#                    }
#                }
#            }
#
#            if (crossAccountRole && !restrictedAccountPrincipals.length) {
#                helpers.addResult(results, 0,
#                    `Cross-account role "${role.RoleName}" contains trusted account principals only`,
#                    'global', role.Arn);
#            } else if (crossAccountRole) {
#                helpers.addResult(results, 2,
#                    `Cross-account role "${role.RoleName}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
#                    'global', role.Arn);
#            } else {
#                helpers.addResult(results, 0,
#                    `IAM Role "${role.RoleName}" does not contain cross-account statements`,
#                    'global', role.Arn);
#            }
#        });
#        
#        callback(null, results, source);
#    }