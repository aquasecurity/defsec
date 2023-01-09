# METADATA
# title :"ElasticSearch Domain Cross Account access"
# description: "Ensures that only trusted accounts have access to ElasticSearch domains."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-gsg-configure-access.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ES
#   severity: LOW
#   short_code: es-cross-account-access 
#   recommended_action: "Restrict the access to ES clusters to allow only trusted accounts."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config= {
#            es_whitelisted_aws_account_principals : settings.es_whitelisted_aws_account_principals || this.settings.es_whitelisted_aws_account_principals.default,
#            es_whitelisted_aws_account_principals_regex : settings.es_whitelisted_aws_account_principals_regex || this.settings.es_whitelisted_aws_account_principals_regex.default,
#            es_whitelist_aws_organization_accounts: settings.es_whitelist_aws_organization_accounts || this.settings.es_whitelist_aws_organization_accounts.default,
#            es_policy_condition_keys: settings.es_policy_condition_keys || this.settings.es_policy_condition_keys.default,
#        };
#        var allowedConditionKeys = config.es_policy_condition_keys.split(',');
#        var makeRegexBased = (config.es_whitelisted_aws_account_principals_regex.length) ? true : false;
#        var whitelistOrganization = (config.es_whitelist_aws_organization_accounts == 'true'); 
#        config.es_whitelisted_aws_account_principals_regex = new RegExp(config.es_whitelisted_aws_account_principals_regex);
#        
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var defaultRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', regions.default, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#        let organizationAccounts = [];
#        if (whitelistOrganization) {
#            var listAccounts = helpers.addSource(cache, source,
#                ['organizations', 'listAccounts', defaultRegion]);
#
#            if (!listAccounts || listAccounts.err || !listAccounts.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, defaultRegion);
#                return callback(null, results, source);
#            }
#            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
#        }
#
#        async.each(regions.es, function(region, rcb) {
#            var listDomainNames = helpers.addSource(cache, source,
#                ['es', 'listDomainNames', region]);
#
#            if (!listDomainNames) return rcb();
#            if (listDomainNames.err || !listDomainNames.data) {
#                helpers.addResult(
#                    results, 3,
#                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
#                return rcb();
#            }
#
#            if (!listDomainNames.data.length){
#                helpers.addResult(results, 0, 'No ES domains found', region);
#                return rcb();
#            }
#
#            listDomainNames.data.forEach(domain => {
#                if (!domain.DomainName) return;
#
#                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
#
#                var describeElasticsearchDomain = helpers.addSource(cache, source,
#                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);
#
#                if (!describeElasticsearchDomain ||
#                    describeElasticsearchDomain.err ||
#                    !describeElasticsearchDomain.data ||
#                    !describeElasticsearchDomain.data.DomainStatus) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
#                } else {
#                    var localDomain = describeElasticsearchDomain.data.DomainStatus;
#                   
#                    if (!localDomain.AccessPolicies)  {                        
#                        helpers.addResult(results, 0,
#                            'ES domain does not have access policy defined', region, resource);
#                        return;
#                    }
#                           
#                    var statements = helpers.normalizePolicyDocument(localDomain.AccessPolicies);
#        
#                    if (!statements){
#                        helpers.addResult(results, 0, 'No statement exists for the policy', region, resource);
#                        return;
#                    }
#
#                    var restrictedAccountPrincipals = [];
#                    var crossAccountEs = false;
#        
#                    statements.forEach(statement => {
#                        if (!statement.Principal) return;
#    
#                        let conditionalPrincipals = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId);
#                        if (helpers.crossAccountPrincipal(statement.Principal, accountId) ||
#                            (conditionalPrincipals && conditionalPrincipals.length)) {
#                            let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
#
#                            if (conditionalPrincipals && conditionalPrincipals.length) {
#                                conditionalPrincipals.forEach(conPrincipal => {
#                                    if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
#                                });
#                            }
#
#                            if (!crossAccountPrincipals.length) return;
#                            crossAccountEs = true;
#                            crossAccountPrincipals.forEach(principal => {
#                                if (whitelistOrganization) {
#                                    if (organizationAccounts.find(account => principal.includes(account))) return;
#                                }
#                                if (makeRegexBased) {
#                                    if (!config.es_whitelisted_aws_account_principals_regex.test(principal) &&
#                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                                } else if (!config.es_whitelisted_aws_account_principals.includes(principal) &&
#                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                            });
#                        }
#                    });
#
#                    if (crossAccountEs && !restrictedAccountPrincipals.length) {
#                        helpers.addResult(results, 0,
#                            'ES domain contains trusted account principals only', region, resource);
#                    } else if (crossAccountEs) {
#                        helpers.addResult(results, 2,
#                            `ES domain contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`, region,resource);
#                    } else {
#                        helpers.addResult(results, 0,
#                            'ES domain does not contain cross-account policy statement', region, resource);
#                    }
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }