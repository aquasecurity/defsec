# METADATA
# title :"Image Recipe Storage Volumes Encrypted"
# description: "Ensure that Image Recipe storage ebs volumes are encrypted."
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
#   short_code: image-recipe-volume-encrypted 
#   recommended_action: "Ensure that storage volumes for ebs are encrypted using AWS keys or customer managed keys in Image recipe"
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
#            desiredEncryptionLevelString: settings.image_recipe_ebs_volumes_desired_encryption_level || this.settings.image_recipe_ebs_volumes_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.imagebuilder, function(region, rcb){        
#            var listImageRecipes = helpers.addSource(cache, source,
#                ['imagebuilder', 'listImageRecipes', region]);
#
#            if (!listImageRecipes) return rcb();
#
#            if (listImageRecipes.err || !listImageRecipes.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for image recipe summary list: ${helpers.addError(listImageRecipes)}`, region);
#                return rcb();
#            }
#
#            if (!listImageRecipes.data.length) {
#                helpers.addResult(results, 0, 'No Image Builder image recipes found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys:' + helpers.addError(listKeys), region);
#                return rcb();
#            }   
#
#            var listAliases = helpers.addSource(cache, source,
#                ['kms', 'listAliases', region]);
#
#            if (!listAliases || listAliases.err || !listAliases.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for KMS aliases: ' + helpers.addError(listAliases),
#                    region);
#                return rcb();
#            }
#            
#            var keyArn;
#            var kmsAliasArnMap = {};
#            listAliases.data.forEach(function(alias){
#                keyArn = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
#                kmsAliasArnMap[alias.AliasName] = keyArn;
#            });
#
#            for (let recipe of listImageRecipes.data) {
#                if (!recipe.arn) continue;
#
#                let resource = recipe.arn;
#                var getImageRecipe = helpers.addSource(cache, source,
#                    ['imagebuilder', 'getImageRecipe', region, recipe.arn]);
#
#                if (!getImageRecipe || getImageRecipe.err || !getImageRecipe.data || !getImageRecipe.data.imageRecipe) {
#                    helpers.addResult(results, 3,
#                        `Unable to get image Recipe description: ${helpers.addError(getImageRecipe)}`,
#                        region, resource);
#                    continue;
#                } 
#                let poorlyEncrypted = [];
#                for (let mapping of getImageRecipe.data.imageRecipe.blockDeviceMappings){
#                    if (mapping.ebs && !mapping.ebs.encrypted){
#                        poorlyEncrypted.push(mapping.ebs);
#                        continue;
#                    } 
#
#                    if (mapping.ebs && mapping.ebs.kmsKeyId && mapping.ebs.kmsKeyId.includes('alias/aws/ebs')){
#                        currentEncryptionLevel = 2;
#                    } else {
#                        var encryptionKey = mapping.ebs.kmsKeyId;
#                        var encryptionKeyArr = encryptionKey.split(':');
#                        encryptionKey = encryptionKeyArr[encryptionKeyArr.length-1];
#                        let kmsKeyArn = (encryptionKey.includes('alias/')) ?
#                            (kmsAliasArnMap[encryptionKey]) ? kmsAliasArnMap[encryptionKey] :
#                                encryptionKey : encryptionKey;
#                        
#                        var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, keyId]);
#                            
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, kmsKeyArn);
#                            continue;
#                        }
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    } 
#                }
#            
#                if (poorlyEncrypted.length){
#                    helpers.addResult(results, 2,
#                        'Image recipe : ' + poorlyEncrypted.length + ' ebs volumes does not have encryption enabled',
#                        region, resource);
#                    continue;
#                }  
# 
#                let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Image recipe ebs volumes are encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Image recipe ebs volumes are encrypted with ${currentEncryptionLevelString} \
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