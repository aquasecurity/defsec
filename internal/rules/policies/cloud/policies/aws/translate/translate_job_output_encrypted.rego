# METADATA
# title :"Translate Job Output Encrypted"
# description: "Ensure that your Amazon Translate jobs have CMK encryption enabled for output data residing on S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/translate/latest/dg/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Translate
#   severity: LOW
#   short_code: translate-job-output-encrypted 
#   recommended_action: "Create Translate jobs with customer-manager keys (CMKs)."
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
#            desiredEncryptionLevelString: settings.translate_job_encryption_level || this.settings.translate_job_encryption_level.default
#        };
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.translate, function(region, rcb){
#            var listTextTranslationJobs = helpers.addSource(cache, source,
#                ['translate', 'listTextTranslationJobs', region]);
#
#            if (!listTextTranslationJobs) return rcb();
#
#            if (listTextTranslationJobs.err || !listTextTranslationJobs.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list Translate text jobs: ${helpers.addError(listTextTranslationJobs)}`, region);
#                return rcb();
#            }
#
#            if (!listTextTranslationJobs.data.length) {
#                helpers.addResult(results, 0,
#                    'No Translate text jobs found', region);
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
#            for (let job of listTextTranslationJobs.data) {
#                if (!job.JobName) continue;
#
#                var resource = `arn:${awsOrGov}:translate:${region}:${accountId}:job/${job.JobName}`;
#
#                if (job.OutputDataConfig) {
#                    if (job.OutputDataConfig && job.OutputDataConfig.EncryptionKey && job.OutputDataConfig.EncryptionKey.Id) {
#                        var kmsKeyId = job.OutputDataConfig.EncryptionKey.Id.split('/')[1] ? job.OutputDataConfig.EncryptionKey.Id.split('/')[1] : job.OutputDataConfig.EncryptionKey.Id;
#    
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, kmsKeyId]);
#    
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, job.OutputDataConfig.EncryptionKey.Id);
#                            continue;
#                        }
#    
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    } else {
#                        currentEncryptionLevel = 2; //awskms
#                    }
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#    
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Translate job is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Translate job is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 3,
#                        'Unable to find output data config for the job',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }