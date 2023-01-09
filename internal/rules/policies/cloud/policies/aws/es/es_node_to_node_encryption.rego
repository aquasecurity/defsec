# METADATA
# title :"ElasticSearch Node To Node Encryption"
# description: "Ensures ElasticSearch domain traffic is encrypted in transit between nodes"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ES
#   severity: LOW
#   short_code: es-node-to-node-encryption 
#   recommended_action: "Ensure node-to-node encryption is enabled for all ElasticSearch domains."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
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
#                    if (localDomain.NodeToNodeEncryptionOptions &&
#                        localDomain.NodeToNodeEncryptionOptions.Enabled) {
#                        helpers.addResult(results, 0,
#                            'ES domain is configured to use node-to-node encryption', region, localDomain.ARN);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'ES domain is not configured to use node-to-node encryption', region, localDomain.ARN);
#                    }
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }