# METADATA
# title :"AWS Glue Data Catalog CMK Encrypted"
# description: "Ensures that AWS Glue has data catalog encryption enabled with KMS Customer Master Key (CMK)."
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
#   short_code: data-catalog-cmk-encrypted 
#   recommended_action: "Modify Glue data catalog to use CMK instead of AWS-managed Key to encrypt Metadata"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
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
#                encryptionSettings.EncryptionAtRest.CatalogEncryptionMode.toUpperCase() !== 'DISABLED') {
#
#                var kmsKeyId = encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId.split('/')[1];
#
#                var describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, kmsKeyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data ||
#                    !describeKey.data.KeyMetadata || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                        region, kmsKeyId);
#                    return rcb();
#                }
#
#                if (helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS) == 3) {
#                    helpers.addResult(results, 0,
#                        'Glue data catalog has encryption at-rest enabled for metadata using Customer Master Key',
#                        region);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Glue data catalog has encryption at-rest enabled for metadata using AWS-managed key',
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