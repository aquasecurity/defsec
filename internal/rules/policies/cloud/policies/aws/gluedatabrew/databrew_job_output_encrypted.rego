# METADATA
# title :"AWS Glue DataBrew Job Output Encrypted"
# description: "Ensure that AWS Glue DataBrew jobs have encryption enabled for output files with desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/databrew/latest/dg/encryption-security-configuration.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Glue DataBrew
#   severity: LOW
#   short_code: databrew-job-output-encrypted 
#   recommended_action: "Modify Glue DataBrew jobs to set desired encryption configuration"
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
#            desiredEncryptionLevelString: settings.databrew_job_encryption_level || this.settings.databrew_job_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.databrew, function(region, rcb){
#            var listJobs = helpers.addSource(cache, source,
#                ['databrew', 'listJobs', region]);
#
#            if (!listJobs) return rcb();
#
#            if (listJobs.err || !listJobs.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list DataBrew jobs: ${helpers.addError(listJobs)}`, region);
#                return rcb();
#            }
#
#            if (!listJobs.data.length) {
#                helpers.addResult(results, 0,
#                    'No DataBrew jobs found', region);
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
#            for (let job of listJobs.data) {
#                if (!job.ResourceArn) continue;
#
#                var resource = job.ResourceArn;
#
#                if (job.EncryptionMode) {
#                    if (job.EncryptionKeyArn) {
#                        var kmsKeyId = job.EncryptionKeyArn.split('/')[1] ? job.EncryptionKeyArn.split('/')[1] : job.EncryptionKeyArn;
#
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, kmsKeyId]);
#
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, job.EncryptionKeyArn);
#                            continue;
#                        }
#
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    } else {
#                        currentEncryptionLevel = 1; //s3-sse
#                    }
#
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `DataBrew job is using ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `DataBrew job is using ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'DataBrew job does not have encryption enabled for output file',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }