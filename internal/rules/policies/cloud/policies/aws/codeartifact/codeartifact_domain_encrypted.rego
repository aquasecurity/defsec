# METADATA
# title :"CodeArtifact Domain Encrypted"
# description: "Ensures that AWS CodeArtifact domains have encryption enabled with desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/codeartifact/latest/ug/domain-create.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CodeArtifact
#   severity: LOW
#   short_code: codeartifact-domain-encrypted 
#   recommended_action: "Encrypt CodeArtifact domains with desired encryption level"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            desiredEncryptionLevelString: settings.codeartifact_domain_encryption_level || this.settings.codeartifact_domain_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.codeartifact, function(region, rcb){
#            var listDomains = helpers.addSource(cache, source,
#                ['codeartifact', 'listDomains', region]);
#
#            if (!listDomains) return rcb();
#
#            if (listDomains.err || !listDomains.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list CodeArtifact domains: ${helpers.addError(listDomains)}`, region);
#                return rcb();
#            }
#
#            if (!listDomains.data.length) {
#                helpers.addResult(results, 0,
#                    'No CodeArtifact domains found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                return rcb();
#            }
#
#            for (let domain of listDomains.data) {
#                if (!domain.arn) continue;
#
#                let resource = domain.arn;
#                if (domain.encryptionKey) {
#                    var kmsKeyId = domain.encryptionKey.split('/')[1] ? domain.encryptionKey.split('/')[1] : domain.encryptionKey;
#    
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);
#    
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, domain.encryptionKey);
#                        continue;
#                    }
#    
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#    
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `CodeArtifact domain is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `CodeArtifact domain is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'CodeArtifact domain does not have encryption enabled for assets',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }