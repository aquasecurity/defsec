# METADATA
# title :"Model Data Encrypted"
# description: "Ensure that Lookout for Vision model data is encrypted using desired KMS encryption level"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lookout-for-vision/latest/developer-guide/security-data-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Lookout
#   severity: LOW
#   short_code: model-data-encrypted 
#   recommended_action: "Encrypt LookoutVision model with customer-manager keys (CMKs) present in your account"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.regions(settings);
#
#        var config = {
#            desiredEncryptionLevelString: settings.model_data_desired_encryption_level || this.settings.model_data_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(region.lookoutvision, function(region, rcb){
#            var listProjects = helpers.addSource(cache, source,
#                ['lookoutvision', 'listProjects', region]);
#
#            if (!listProjects) return rcb();
#
#            if (listProjects.err || !listProjects.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Lookout for Vision projects: ' + helpers.addError(listProjects), region);
#                return rcb();
#            }
#
#            if (!listProjects.data.length) {
#                helpers.addResult(results, 0, 'No Lookout for Vision projects found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
#                return rcb();
#            }
#    
#            for (let project of listProjects.data){
#                if (!project.ProjectName) continue;
#
#                let projectArn = project.ProjectArn;
#
#                var listModels = helpers.addSource(cache, source,
#                    ['lookoutvision', 'listModels', region, project.ProjectName]);
#
#                if (!listModels || listModels.err || !listModels.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for Lookout for Vision models: ' + project.ProjectName + ': ' + helpers.addError(listModels),
#                        region, projectArn);
#                    continue;
#                }
#
#                if (!listModels.data.Models || !listModels.data.Models.length) {
#                    helpers.addResult(results, 0,
#                        'No models found for Lookout for Vision project',
#                        region, projectArn);
#                    continue;
#                }
#
#                for (let model of listModels.data.Models) {
#                    if (!model.ModelArn) continue;
#
#                    let resource = model.ModelArn;
#
#                    var describeModel = helpers.addSource(cache, source,
#                        ['lookoutvision', 'describeModel', region, model.ModelArn]);
#
#                    if (!describeModel ||
#                        describeModel.err ||
#                        !describeModel.data || !describeModel.data.ModelDescription) {
#                        helpers.addResult(results, 3,
#                            'Unable to get Lookout for Vision models: ' + helpers.addError(describeModel), region, resource);
#                        continue;
#                    }
#
#                    if (describeModel.data.ModelDescription.KmsKeyId) {
#                        let kmsKey =  describeModel.data.ModelDescription.KmsKeyId;
#                        let keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;
#
#                        let describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, keyId]);  
#
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, kmsKey);
#                            continue;
#                        }
#
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#                    } else {
#                        currentEncryptionLevel = 1; //sse
#                    }
#
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Model data is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Model data is encrypted with ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }