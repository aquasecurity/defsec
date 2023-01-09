# METADATA
# title :"Forecast Dataset Export Encrypted"
# description: "Ensure that AWS Forecast exports have encryption enabled before they are being saved on S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/forecast/latest/dg/howitworks-forecast.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Forecast
#   severity: LOW
#   short_code: dataset-export-encrypted 
#   recommended_action: "Create Forecast exports with encryption enabled"
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
#            desiredEncryptionLevelString: settings.forecast_dataset_desired_encryption_level || this.settings.forecast_dataset_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.forecastservice, function(region, rcb){
#            var listForecastExportJobs = helpers.addSource(cache, source,
#                ['forecastservice', 'listForecastExportJobs', region]);
#
#            if (!listForecastExportJobs) return rcb();
#
#            if (listForecastExportJobs.err || !listForecastExportJobs.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query Forecast exports: ' + helpers.addError(listForecastExportJobs), region);
#                return rcb();
#            }
#
#            if (!listForecastExportJobs.data.length) {
#                helpers.addResult(results, 0, 'No Forecast exports found', region);
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
#            for (let forecastExportJob of listForecastExportJobs.data) {
#                if (!forecastExportJob.Destination) {
#                    continue;
#                }
#
#                let { S3Config } = forecastExportJob.Destination;
#                let resource = forecastExportJob.ForecastExportJobArn;
#
#                if (S3Config && S3Config.KMSKeyArn) {
#                    let encryptionKey = S3Config.KMSKeyArn;
#                    var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, encryptionKey);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Forecast dataset export is encrypted with ${currentEncryptionLevelString} \
#                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Forecast dataset export is encrypted with ${currentEncryptionLevelString} \
#                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Forecast dataset export does not have encryption enabled', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }