# METADATA
# title :"Project Artifacts Encrypted"
# description: "Ensure that your AWS CodeBuild project artifacts are encrypted with desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CodeBuild
#   severity: LOW
#   short_code: project-artifacts-encrypted 
#   recommended_action: "Encrypt them using customer-managed keys to gain more control over data encryption and decryption process."
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
#            desiredEncryptionLevelString: settings.project_artifacts_desired_encryption_level || this.settings.project_artifacts_desired_encryption_level.default
#        };
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#   
#        async.each(regions.codebuild, function(region, rcb){
#            var listProjects = helpers.addSource(cache, source,
#                ['codebuild', 'listProjects', region]);
#            
#            if (!listProjects) return rcb();
#
#            if (listProjects.err || !listProjects.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list CodeBuild projects: ${helpers.addError(listProjects)}`, region);
#                return rcb();
#            }
#
#            if (!listProjects.data.length) {
#                helpers.addResult(results, 0,
#                    'No CodeBuild projects found', region);
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
#            for (let project of listProjects.data) {
#                var resource = `arn:${awsOrGov}:codebuild:${region}:${accountId}:project/${project}`;
#
#                let batchGetProjects = helpers.addSource(cache, source,
#                    ['codebuild', 'batchGetProjects', region, project]);
#
#                if (!batchGetProjects || batchGetProjects.err || !batchGetProjects.data ||
#                    !batchGetProjects.data.projects || !batchGetProjects.data.projects.length) {
#                    helpers.addResult(results, 3,
#                        `Unable to query CodeBuild project: ${helpers.addError(batchGetProjects)}`, region, resource);
#                    continue;
#                }
#                
#                if (batchGetProjects.data.projects[0].encryptionKey && batchGetProjects.data.projects[0].encryptionKey.includes('alias/aws/s3')) {
#                    currentEncryptionLevel = 2; //awskms
#                } else if (batchGetProjects.data.projects[0].encryptionKey) {
#                    let kmsKeyArn = batchGetProjects.data.projects[0].encryptionKey;
#                    var kmsKeyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKeyArn);
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
#                        `CodeBuild project artifacts are encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `CodeBuild project artifacts are encrypted with ${currentEncryptionLevelString} \
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