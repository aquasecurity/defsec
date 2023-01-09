# METADATA
# title :"CloudWatch Log Groups Encrypted"
# description: "Ensure that the CloudWatch Log groups are encrypted using desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudWatchLogs
#   severity: LOW
#   short_code: log-groups-encrypted 
#   recommended_action: "Ensure CloudWatch Log groups have encryption enabled with desired AWS KMS key"
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
#            desiredEncryptionLevelString: settings.cloudwatchlog_groups_desired_encryption_level || this.settings.cloudwatchlog_groups_desired_encryption_level.default,
#            cloudwatchlog_whitelist: settings.cloudwatchlog_whitelist || this.settings.cloudwatchlog_whitelist.default
#        };
#
#        if (config.cloudwatchlog_whitelist &&
#            config.cloudwatchlog_whitelist.length) {
#            config.cloudwatchlog_whitelist = config.cloudwatchlog_whitelist.split(',');
#        } else {
#            config.cloudwatchlog_whitelist = [];
#        }
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.cloudwatchlogs, function(region, rcb){
#            var describeLogGroups = helpers.addSource(cache, source,
#                ['cloudwatchlogs', 'describeLogGroups', region]);
#
#            if (!describeLogGroups) return rcb();
#
#            if (describeLogGroups.err || !describeLogGroups.data) {
#                helpers.addResult(results, 3, `Unable to query CloudWatch log groups: ${helpers.addError(describeLogGroups)}`, region);
#                return rcb();
#            }
#
#            if (!describeLogGroups.data.length) {
#                helpers.addResult(results, 0, 'No CloudWatch log groups found', region);
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
#            for (let logGroup of describeLogGroups.data) {
#                if (!logGroup.arn) continue;
#                let resource = logGroup.arn;
#
#                let whitelisted = false;
#                if (config.cloudwatchlog_whitelist.length) {
#                    config.cloudwatchlog_whitelist.forEach(whitelist => {
#                        if (resource.indexOf(whitelist) > -1) {
#                            whitelisted = true;
#                        }
#                    });
#                }
#
#                if (whitelisted) {
#                    helpers.addResult(results, 0,
#                        'The cloudwatch log group is whitelisted.',
#                        region, resource);
#                    return rcb();
#                }
#
#                if (!logGroup.kmsKeyId) {
#                    currentEncryptionLevel = 2; //awskms
#                } else {
#                    var kmsKeyId = logGroup.kmsKeyId.split('/')[1] ? logGroup.kmsKeyId.split('/')[1] : logGroup.kmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, logGroup.kmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `CloudWatch log group is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `CloudWatch log group is encrypted with ${currentEncryptionLevelString} \
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