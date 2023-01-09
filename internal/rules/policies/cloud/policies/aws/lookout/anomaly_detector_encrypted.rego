# METADATA
# title :"LookoutMetrics Anomaly Detector Encrypted"
# description: "Ensure that Amazon LookoutMetrics Anomaly Detector is encrypted using desired KMS encryption level"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lookoutmetrics/latest/dev/security-dataprotection.html#security-privacy-atrest
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:LookoutMetrics
#   severity: LOW
#   short_code: anomaly-detector-encrypted 
#   recommended_action: "Encrypt Amazon LookoutMetrics Anomaly Detector with customer-manager keys (CMKs)"
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
#            desiredEncryptionLevelString: settings.lookoutmetrics_anomalydetectors_desired_encryption_level || this.settings.lookoutmetrics_anomalydetectors_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.lookoutmetrics, function(region, rcb){        
#            var listAnomalyDetectors = helpers.addSource(cache, source,
#                ['lookoutmetrics', 'listAnomalyDetectors', region]);
#
#            if (!listAnomalyDetectors) return rcb();
#
#            if (listAnomalyDetectors.err || !listAnomalyDetectors.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query LookoutMetrics Anomaly Detector: ' + helpers.addError(listAnomalyDetectors), region);
#                return rcb();
#            }
#
#            if (!listAnomalyDetectors.data.length) {
#                helpers.addResult(results, 0, 'No LookoutMetrics Anomaly Detectors found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                return rcb();
#            }
#
#            for (let detector of listAnomalyDetectors.data) {
#                if (!detector.AnomalyDetectorArn) continue;
#
#                let resource = detector.AnomalyDetectorArn;
#
#                var describeAnomalyDetector = helpers.addSource(cache, source,
#                    ['lookoutmetrics', 'describeAnomalyDetector', region, detector.AnomalyDetectorArn]);
#
#                if (!describeAnomalyDetector || describeAnomalyDetector.err || !describeAnomalyDetector.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get LookoutMetrics Anomaly Detector: ${helpers.addError(describeAnomalyDetector)}`,
#                        region, resource);
#                    continue;
#                } 
#
#                if (describeAnomalyDetector.data.KmsKeyArn) {
#                    var KmsKey = describeAnomalyDetector.data.KmsKeyArn;
#                    var keyId = KmsKey.split('/')[1] ? KmsKey.split('/')[1] : KmsKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, KmsKey);
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
#                        `LookoutMetrics Anomaly Detector is using ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `LookoutMetrics Anomaly Detector is using ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }