# METADATA
# title :"ElasticSearch TLS Version"
# description: "Ensure ElasticSearch domain is using the latest security policy to only allow TLS v1.2"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/infrastructure-security.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ES
#   severity: LOW
#   short_code: es-tls-version 
#   recommended_action: "Update elasticsearch domain to set TLSSecurityPolicy to contain TLS version 1.2."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        const results = [];
#        const source = {};
#        const regions = helpers.regions(settings);
#
#        const acctRegion = helpers.defaultRegion(settings);
#        const accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        const awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.es, function(region, rcb) {
#            const listDomainNames = helpers.addSource(cache, source,
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
#            async.each(listDomainNames.data, function(domain, cb){
#                if (!domain.DomainName) return cb();
#
#                const describeElasticsearchDomain = helpers.addSource(cache, source,
#                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);
#
#                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
#
#                if (!describeElasticsearchDomain ||
#                    describeElasticsearchDomain.err ||
#                    !describeElasticsearchDomain.data ||
#                    !describeElasticsearchDomain.data.DomainStatus) {
#                    helpers.addResult(
#                        results, 3,
#                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
#                    return cb();
#                }
#                if (describeElasticsearchDomain.data.DomainStatus.DomainEndpointOptions &&
#                    describeElasticsearchDomain.data.DomainStatus.DomainEndpointOptions.TLSSecurityPolicy &&
#                    describeElasticsearchDomain.data.DomainStatus.DomainEndpointOptions.TLSSecurityPolicy == 'Policy-Min-TLS-1-2-2019-07') {
#                    helpers.addResult(results, 0,
#                        'ES domain is using TLS version 1.2', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'ES domain is not using TLS version 1.2', region, resource);
#                }
#
#                cb();
#            }, function() {
#                rcb();
#            });
#
#        }, function() {
#            callback(null, results, source);
#        });
#    }