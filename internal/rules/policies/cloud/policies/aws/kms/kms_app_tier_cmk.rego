# METADATA
# title :"App-Tier KMS Customer Master Key (CMK)"
# description: "Ensures that there is one Amazon KMS Customer Master Key (CMK) present in the account for App-Tier resources."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:KMS
#   severity: LOW
#   short_code: kms-app-tier-cmk 
#   recommended_action: "Create a Customer Master Key (CMK) with App-Tier tag"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var config = {
#            kms_cmk_tag_key: settings.kms_cmk_tag_key || this.settings.kms_cmk_tag_key.default
#        };
#
#        if (!config.kms_cmk_tag_key.length) return callback(null, results, source);
#
#        async.each(regions.kms, function(region, rcb){
#            var getTagKeys = helpers.addSource(cache, source,
#                ['resourcegroupstaggingapi', 'getTagKeys', region]);
#
#            if (!getTagKeys) return rcb();
#
#            if (getTagKeys.err || !getTagKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to get tag keys: ${helpers.addError(getTagKeys)}`, region);
#                return rcb();
#            }
#
#            if (!getTagKeys.data.length) {
#                helpers.addResult(results, 0, 'No tag keys found', region);
#                return rcb();
#            }
#
#            if (!getTagKeys.data.includes(config.kms_cmk_tag_key)) {
#                helpers.addResult(results, 2,
#                    `No key with "${config.kms_cmk_tag_key}" tag found`, region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys) return rcb();
#
#            if (listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!listKeys.data.length) {
#                helpers.addResult(results, 2, 'No KMS keys found', region);
#                return rcb();
#            }
#
#            var appTierKmsKey = false;
#
#            async.each(listKeys.data, function(kmsKey, kcb){
#                var listResourceTags = helpers.addSource(cache, source,
#                    ['kms', 'listResourceTags', region, kmsKey.KeyId]);
#                
#                if (!listResourceTags || listResourceTags.err || !listResourceTags.data || !listResourceTags.data.Tags) {
#                    helpers.addResult(results, 3,
#                        `Unable to describe resource tags: ${helpers.addError(listResourceTags)}`,
#                        region, kmsKey.KeyArn);
#                    return kcb();
#                }
#
#                if (listResourceTags.data.Tags.length) {
#                    for (var i in listResourceTags.data.Tags) {
#                        var kmsTag = listResourceTags.data.Tags[i];
#                        if (kmsTag.TagKey && kmsTag.TagKey === config.kms_cmk_tag_key) {
#                            appTierKmsKey = true;
#                            return kcb();
#                        }
#                    }
#                }
#
#                kcb();
#            }, function(){
#                if (appTierKmsKey) {
#                    helpers.addResult(results, 0,
#                        `KMS Customer Master key with "${config.kms_cmk_tag_key}" tag is present`,
#                        region);
#                } else {
#                    helpers.addResult(results, 2,
#                        `No KMS Customer Master key with "${config.kms_cmk_tag_key}" tag found`,
#                        region);
#                }
#
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }