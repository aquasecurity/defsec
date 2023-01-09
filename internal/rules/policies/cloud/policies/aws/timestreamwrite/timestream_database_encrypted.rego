# METADATA
# title :"Timestream Database Encrypted"
# description: "Ensure that AWS Timestream databases are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Timestream
#   severity: LOW
#   short_code: timestream-database-encrypted 
#   recommended_action: "Modify Timestream database encryption configuration to use desired encryption key"
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
#            desiredEncryptionLevelString: settings.timestream_databases_desired_encryption_level || this.settings.timestream_databases_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.timestreamwrite, function(region, rcb){
#            var listDatabases = helpers.addSource(cache, source,
#                ['timestreamwrite', 'listDatabases', region]);
#               
#            if (!listDatabases) return rcb();
#
#            if (listDatabases.err || !listDatabases.data) {
#                helpers.addResult(results, 3, `Unable to query Timestream databases: ${helpers.addError(listDatabases)}`, region);
#                return rcb();
#            }
#
#            if (!listDatabases.data.length) {
#                helpers.addResult(results, 0, 'No Timestream databases found', region);
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
#            for (let database of listDatabases.data) {
#                if (!database.Arn) continue;
#
#                let resource = database.Arn;
#
#                if (database.KmsKeyId) {
#                    var kmsKeyId = database.KmsKeyId.split('/')[1] ? database.KmsKeyId.split('/')[1] : database.KmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, database.KmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                } else {
#                    currentEncryptionLevel = 2; //awskms
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Timestream database is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Timestream database is encrypted with ${currentEncryptionLevelString} \
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