# METADATA
# title :"AWS Glue Data Catalog Encryption Enabled"
# description: "Ensures that AWS Glue Data Catalogs has encryption at-rest enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Glue
#   severity: LOW
#   short_code: data-catalog-encryption-enabled 
#   recommended_action: "Modify Glue data catalog settings and enable metadata encryption"
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
#            desiredEncryptionLevelString: settings.glue_datacatalog_encryption_level || this.settings.glue_datacatalog_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.glue, function(region, rcb){
#            var getDataCatalogEncryptionSettings = helpers.addSource(cache, source,
#                ['glue', 'getDataCatalogEncryptionSettings', region]);
#
#            if (!getDataCatalogEncryptionSettings) return rcb();
#
#            if (getDataCatalogEncryptionSettings.err || !getDataCatalogEncryptionSettings.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Glue data catalog encryption settings: ${helpers.addError(getDataCatalogEncryptionSettings)}`, region);
#                return rcb();
#            }
#
#            var encryptionSettings = getDataCatalogEncryptionSettings.data;
#
#            if (encryptionSettings && encryptionSettings.EncryptionAtRest &&
#                encryptionSettings.EncryptionAtRest.CatalogEncryptionMode &&
#                encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId &&
#                encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId.length &&
#                encryptionSettings.EncryptionAtRest.CatalogEncryptionMode.toUpperCase() !== 'DISABLED') {
#
#                var kmsKeyId = encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId.split('/')[1] ? encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId.split('/')[1] : encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId;
#
#                var describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, kmsKeyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                        region, kmsKeyId);
#                    return rcb();
#                }
#
#                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Glue data catalog has encryption at-rest enabled for metadata at encryption level ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Glue data catalog has encryption at-rest enabled for metadata at encryption level ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region);
#                }
#            } else {
#                helpers.addResult(results, 2,
#                    'Glue data catalog does not have encryption at-rest enabled for metadata',
#                    region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }