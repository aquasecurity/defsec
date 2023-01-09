# METADATA
# title :"Service Encrypted"
# description: "Ensure that AWS App Runner service is encrypted using using desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/apprunner/latest/dg/security-data-protection-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:App Runner
#   severity: LOW
#   short_code: service-encrypted 
#   recommended_action: "Create App Runner Service with customer-manager keys (CMKs)"
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
#            desiredEncryptionLevelString: settings.app_runner_service_desired_encryption_level || this.settings.app_runner_service_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.apprunner, function(region, rcb){        
#            var listServices = helpers.addSource(cache, source,
#                ['apprunner', 'listServices', region]);
#
#            if (!listServices) return rcb();
#
#            if (listServices.err || !listServices.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query Service: ' + helpers.addError(listServices), region);
#                return rcb();
#            }
#
#            if (!listServices.data.length) {
#                helpers.addResult(results, 0, 'No Service found', region);
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
#            for (let service of listServices.data) {
#                if (!service.ServiceArn) continue;
#
#                let resource = service.ServiceArn;
#
#                var describeService = helpers.addSource(cache, source,
#                    ['apprunner', 'describeService', region, service.ServiceArn]);
#
#                if (!describeService || describeService.err || !describeService.data ) {
#                    helpers.addResult(results, 3,
#                        `Unable to get Service description: ${helpers.addError(describeService)}`,
#                        region, resource);
#                    continue;
#                } 
#
#                if (describeService.data.Service && describeService.data.Service.EncryptionConfiguration &&
#                    describeService.data.Service.EncryptionConfiguration.KmsKey) {
#
#                    var kmsKey = describeService.data.Service.EncryptionConfiguration.KmsKey;
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
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                } else {
#
#                    currentEncryptionLevel = 2; //awskms
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `App Runner service is using ${currentEncryptionLevelString} for encryption \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `App Runner service is using ${currentEncryptionLevelString} for encryption \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }