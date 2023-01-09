# METADATA
# title :"ECR Repository Encrypted"
# description: "Ensure that the images in ECR repository are encrypted using desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonECR/latest/userguide/Repositories.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ECR
#   severity: LOW
#   short_code: ecr-repository-encrypted 
#   recommended_action: "Create ECR Repository with customer-manager keys (CMKs)."
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
#            desiredEncryptionLevelString: settings.ecr_repository_desired_encryption_level || this.settings.ecr_repository_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.ecr, function(region, rcb){
#            var describeRepositories = helpers.addSource(cache, source,
#                ['ecr', 'describeRepositories', region]);
#               
#            if (!describeRepositories) return rcb();
#            
#            if (describeRepositories.err || !describeRepositories.data) {
#                helpers.addResult(results, 3, `Unable to query ECR repositories: ${helpers.addError(describeRepositories)}`, region);
#                return rcb();
#            }
#            
#            if (!describeRepositories.data.length) {
#                helpers.addResult(results, 0, 'No ECR repositories found', region);
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
#            for (let repository of describeRepositories.data) {
#                if (!repository.repositoryArn) continue;
#
#                let resource = repository.repositoryArn;
#
#                if (repository.encryptionConfiguration && repository.encryptionConfiguration.kmsKey) {
#                    let kmsKey = repository.encryptionConfiguration.kmsKey;
#                    var keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKey);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                } else {
#                    currentEncryptionLevel = 1; //sse
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `ECR repository is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `ECR repository encrypted with ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }