# METADATA
# title :"Dockerfile Template Encrypted"
# description: "Ensure that Image Recipe dockerfile templates are encrypted."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/imagebuilder/latest/userguide/data-protection.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Image Builder
#   severity: LOW
#   short_code: dockerfile-template-encrypted 
#   recommended_action: "Ensure that container recipe docker file templates are encrypted using AWS keys or customer managed keys in Imagebuilder service"
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
#            desiredEncryptionLevelString: settings.docker_file_desired_encryption_level || this.settings.docker_file_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.imagebuilder, function(region, rcb){        
#            var listContainerRecipes = helpers.addSource(cache, source,
#                ['imagebuilder', 'listContainerRecipes', region]);
#
#            if (!listContainerRecipes) return rcb();
#
#            if (listContainerRecipes.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query container recipe: ' + helpers.addError(listContainerRecipes), region);
#                return rcb();
#            }
#
#            if (!listContainerRecipes.data || !listContainerRecipes.data.length) {
#                helpers.addResult(results, 0, 'No container recipes found', region);
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
#            var listAliases = helpers.addSource(cache, source,
#                ['kms', 'listAliases', region]);
#
#            if (!listAliases || listAliases.err || !listAliases.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
#                    region);
#                return rcb();
#            }
#
#            var keyArn;
#            var kmsAliasArnMap = {};
#            listAliases.data.forEach(function(alias){
#                keyArn = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
#                kmsAliasArnMap[alias.AliasArn] = keyArn;
#            });
#         
#            for (let recipe of listContainerRecipes.data) {
#                let resource = recipe.arn;
#                
#                var getContainerRecipe = helpers.addSource(cache, source,
#                    ['imagebuilder', 'getContainerRecipe', region, recipe.arn]);  
#
#                if (!getContainerRecipe || getContainerRecipe.err || !getContainerRecipe.data ||
#                    !getContainerRecipe.data.containerRecipe) {
#                    helpers.addResult(results, 3,
#                        `Unable to get container recipe description: ${helpers.addError(getContainerRecipe)}`,
#                        region, resource);
#                    continue;
#                }
#
#                if (getContainerRecipe.data.containerRecipe.kmsKeyId) {
#                    var encryptionKey = getContainerRecipe.data.containerRecipe.kmsKeyId;
#                    let kmsKeyArn = (encryptionKey.includes('alias/')) ?
#                        (kmsAliasArnMap[encryptionKey]) ? kmsAliasArnMap[encryptionKey] :
#                            encryptionKey : encryptionKey;
#                
#                    var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKeyArn);
#                        continue;
#                    }
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#                } else currentEncryptionLevel = 2; //awskms
#                            
#                let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Dockerfile Template is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Dockerfile Template is encrypted with ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }