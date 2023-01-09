# METADATA
# title :"Elastic Transcoder Pipeline Data Encrypted"
# description: "Ensure that Elastic Transcoder pipelines have encryption enabled with desired encryption level to encrypt your data."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Elastic Transcoder
#   severity: LOW
#   short_code: pipeline-data-encrypted 
#   recommended_action: "Modify Elastic Transcoder pipelines encryption settings to use custom KMS key"
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
#            desiredEncryptionLevelString: settings.transcoder_pipeline_encryption_level || this.settings.transcoder_pipeline_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.elastictranscoder, function(region, rcb){
#            var listPipelines = helpers.addSource(cache, source,
#                ['elastictranscoder', 'listPipelines', region]);
#
#            if (!listPipelines) return rcb();
#
#            if (listPipelines.err || !listPipelines.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list Elastic Transcoder pipelines: ${helpers.addError(listPipelines)}`, region);
#                return rcb();
#            }
#
#            if (!listPipelines.data.length) {
#                helpers.addResult(results, 0,
#                    'No Elastic Transcoder pipelines found', region);
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
#            for (let pipeline of listPipelines.data) {
#                if (!pipeline.Arn) continue;
#
#                let resource = pipeline.Arn;
#                if (pipeline.AwsKmsKeyArn) {
#                    var kmsKeyId = pipeline.AwsKmsKeyArn.split('/')[1] ? pipeline.AwsKmsKeyArn.split('/')[1] : pipeline.AwsKmsKeyArn;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, pipeline.AwsKmsKeyArn);
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
#                        `Elastic Transcoder Pipeline is using ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Elastic Transcoder Pipeline is using ${currentEncryptionLevelString} \
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