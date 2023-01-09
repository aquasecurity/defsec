# METADATA
# title :"KMS Grant Least Privilege"
# description: "Ensure that AWS KMS key grants use the principle of least privileged access."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:KMS
#   severity: LOW
#   short_code: kms-grant-least-privilege 
#   recommended_action: "Create KMS grants with minimum permission required"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var symmetricOperations = [
#            'Decrypt',
#            'Encrypt',
#            'GenerateDataKey',
#            'GenerateDataKeyPair',
#            'GenerateDataKeyPairWithoutPlaintext',
#            'GenerateDataKeyWithoutPlaintext',
#            'ReEncryptFrom',
#            'ReEncryptTo',
#            'CreateGrant',
#            'DescribeKey',
#            'RetireGrant',
#        ];
#
#        var asymmetricEDOperations = [
#            'Decrypt',
#            'Encrypt',
#            'ReEncryptFrom',
#            'ReEncryptTo',
#            'CreateGrant',
#            'DescribeKey',
#            'GetPublicKey',
#            'RetireGrant',
#        ];
#
#        var asymmetricSVOperations = [ // eslint-disable-line
#            'ReEncryptFrom',
#            'ReEncryptTo',
#            'Sign',
#            'Verify',
#            'CreateGrant',
#            'DescribeKey',
#            'GetPublicKey',
#            'RetireGrant',
#        ];
#
#        async.each(regions.kms, function(region, rcb){
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys) return rcb();
#
#            if (listKeys.err || !listKeys.data){
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
#                return rcb();
#            }
#
#            if (!listKeys.data.length){
#                helpers.addResult(results, 0, 'No KMS keys found', region);
#                return rcb();
#            }
#
#            listKeys.data.forEach(kmsKey => {
#                let resource = kmsKey.KeyArn;
#                let describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, kmsKey.KeyId]);
#            
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for KMS Key: ${helpers.addError(describeKey)}`,
#                        region, resource);
#                    return;
#                }
#
#                let keyLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#                if (keyLevel == 2) {
#                    helpers.addResult(results, 0,
#                        'KMS key is AWS-managed', region, resource);
#                    return;
#                }
#
#                let keySpec = describeKey.data.KeyMetadata.KeySpec;
#                let listGrants = helpers.addSource(cache, source,
#                    ['kms', 'listGrants', region, kmsKey.KeyId]);
#
#                if (!listGrants || listGrants.err || !listGrants.data || !listGrants.data.Grants) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for KMS Key grants: ${helpers.addError(describeKey)}`,
#                        region, resource);
#                    return;
#                }
#
#                if (!listGrants.data.Grants.length) {
#                    helpers.addResult(results, 0,
#                        'No grants exist for the KMS key',
#                        region, resource);
#                    return;
#                }
#
#                let privilegedGrants = [];
#                for (let grant of listGrants.data.Grants) {
#                    if (keySpec && keySpec.startsWith('SYMMETRIC')) {
#                        if (grant.Operations && grant.Operations.length &&
#                            grant.Operations.length >= symmetricOperations.length) privilegedGrants.push(grant.GrantId);
#                    } else {
#                        if (grant.Operations && grant.Operations.length &&
#                            grant.Operations.length >= asymmetricEDOperations.length) privilegedGrants.push(grant.GrantId);
#                    }
#                }
#
#                if (privilegedGrants.length) {
#                    helpers.addResult(results, 2,
#                        `KMS key provides * permission for these grants: ${privilegedGrants.join(', ')}`, region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'KMS key does not provide * permission for any grants', region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }