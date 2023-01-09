# METADATA
# title :"KMS Scheduled Deletion"
# description: "Detects KMS keys that are scheduled for deletion"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:KMS
#   severity: LOW
#   short_code: kms-scheduled-deletion 
#   recommended_action: "Disable the key deletion before the scheduled deletion time."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.kms, function(region, rcb){
#            
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys) return rcb();
#
#            if (listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
#                return rcb();
#            }
#
#            if (!listKeys.data.length) {
#                helpers.addResult(results, 0, 'No KMS keys found', region);
#                return rcb();                
#            }
#
#            async.each(listKeys.data, function(kmsKey, kcb){
#                var describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, kmsKey.KeyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe key: ' + helpers.addError(describeKey),
#                        region, kmsKey.KeyArn);
#                    return kcb();
#                }
#
#                var describeKeyData = describeKey.data;
#
#                // AWS-generated keys for CodeCommit, ACM, etc. should be skipped.
#                // The only way to distinguish these keys is the default description used by AWS.
#                if (describeKeyData.KeyMetadata &&
#                    (describeKeyData.KeyMetadata.Description && describeKeyData.KeyMetadata.Description.indexOf('Default master key that protects my') === 0)) {
#                    return kcb();
#                }
#
#                if (describeKeyData && describeKeyData.KeyMetadata &&
#                    describeKeyData.KeyMetadata.KeyState &&
#                    describeKeyData.KeyMetadata.KeyState == 'PendingDeletion') {
#                    helpers.addResult(results, 1, 'Key is scheduled for deletion', region, kmsKey.KeyArn);
#                } else {
#                    helpers.addResult(results, 0, 'Key is not scheduled for deletion', region, kmsKey.KeyArn);
#                }
#
#                kcb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }