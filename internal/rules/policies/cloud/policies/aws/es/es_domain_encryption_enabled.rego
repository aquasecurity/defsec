# METADATA
# title :"ElasticSearch Encryption Enabled"
# description: "Ensure that AWS ElasticSearch domains have encryption enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ES
#   severity: LOW
#   short_code: es-domain-encryption-enabled 
#   recommended_action: "Ensure encryption-at-rest is enabled for all ElasticSearch domains."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            desiredEncryptionLevelString: settings.es_encryption_level || this.settings.es_encryption_level.default
#        };
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
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
#            listDomainNames.data.forEach(domain => {
#                if (!domain.DomainName) return;
#                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
#
#                var describeElasticsearchDomain = helpers.addSource(cache, source,
#                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);
#                    
#                if (!describeElasticsearchDomain ||
#                    describeElasticsearchDomain.err ||
#                    !describeElasticsearchDomain.data ||
#                    !describeElasticsearchDomain.data.DomainStatus) {
#                    helpers.addResult(
#                        results, 3,
#                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
#                } else {
#                    if (describeElasticsearchDomain.data.DomainStatus &&
#                        describeElasticsearchDomain.data.DomainStatus.EncryptionAtRestOptions &&
#                        describeElasticsearchDomain.data.DomainStatus.EncryptionAtRestOptions.Enabled &&
#                        describeElasticsearchDomain.data.DomainStatus.EncryptionAtRestOptions.KmsKeyId) {
#                        var kmsKeyId = describeElasticsearchDomain.data.DomainStatus.EncryptionAtRestOptions.KmsKeyId.split('/')[1];
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, kmsKeyId]);
#
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`, region, kmsKeyId);
#                            return;
#                        }
#
#                        var currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                        var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                            helpers.addResult(results, 0,
#                                `ES domain has encryption at-rest enabled for data at encryption level ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                                region, resource);
#                        } else {
#                            helpers.addResult(results, 2,
#                                `ES domain has encryption at-rest enabled for data at encryption level ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                                region, resource);
#                        }
#                    } else {
#                        helpers.addResult(results, 2,
#                            'ES domain is not configured to use encryption at rest', region, resource);
#                    }
#                }
#            });
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }