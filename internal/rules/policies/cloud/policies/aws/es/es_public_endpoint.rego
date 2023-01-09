# METADATA
# title :"ElasticSearch Public Service Domain"
# description: "Ensures ElasticSearch domains are created with private VPC endpoint options"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ES
#   severity: LOW
#   short_code: es-public-endpoint 
#   recommended_action: "Configure the ElasticSearch domain to use a VPC endpoint for secure VPC communication."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var config = {
#            allow_es_public_endpoint_if_ip_condition_policy: settings.allow_es_public_endpoint_if_ip_condition_policy || this.settings.allow_es_public_endpoint_if_ip_condition_policy.default
#        };
#
#        config.allow_es_public_endpoint_if_ip_condition_policy = (config.allow_es_public_endpoint_if_ip_condition_policy === 'true' || config.allow_es_public_endpoint_if_ip_condition_policy === true);
#
#        async.each(regions.es, function(region, rcb) {
#            var listDomainNames = helpers.addSource(cache, source,
#                ['es', 'listDomainNames', region]);
#
#            if (!listDomainNames) return rcb();
#
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
#            listDomainNames.data.forEach(function(domain){
#                var describeElasticsearchDomain = helpers.addSource(cache, source,
#                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);
#
#                if (!describeElasticsearchDomain ||
#                    describeElasticsearchDomain.err ||
#                    !describeElasticsearchDomain.data ||
#                    !describeElasticsearchDomain.data.DomainStatus) {
#                    helpers.addResult(
#                        results, 3,
#                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
#                } else {
#                    var localDomain = describeElasticsearchDomain.data.DomainStatus;
#
#                    // assume we have no bad policies
#                    var validPolicy = true;
#
#                    if (config.allow_es_public_endpoint_if_ip_condition_policy &&
#                        localDomain.AccessPolicies) { // evaluate policies if the setting is enabled.
#                        var policies = helpers.normalizePolicyDocument(localDomain.AccessPolicies);
#                        if (!policies) policies = []; // if no policy document then no statements
#
#                        for (var p in policies) {
#                            var policy = policies[p];
#                            var containsIpPolicy = policy.Condition && policy.Condition.IpAddress;
#
#                            if (!containsIpPolicy && helpers.globalPrincipal(policy.Principal)) {
#                                validPolicy = false;
#                            }
#                        }
#                    }
#
#                    if (localDomain.VPCOptions &&
#                        localDomain.VPCOptions.VPCId &&
#                        localDomain.VPCOptions.VPCId.length) {
#                        helpers.addResult(results, 0,
#                            'ES domain is configured to use a VPC endpoint', region, localDomain.ARN);
#                    } else {
#                        if (config.allow_es_public_endpoint_if_ip_condition_policy) {
#                            if (validPolicy) {
#                                helpers.addResult(results, 0,
#                                    'ES domain is configured to use a public endpoint, but is allowed since there are no public access policies.', region, localDomain.ARN);
#                            } else {
#                                helpers.addResult(results, 2,
#                                    'ES domain is configured to use a public endpoint and has disallowed public access policies.', region, localDomain.ARN);
#                            }
#                        } else {
#                            helpers.addResult(results, 2,
#                                'ES domain is configured to use a public endpoint.', region, localDomain.ARN);
#                        }
#                    }
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }