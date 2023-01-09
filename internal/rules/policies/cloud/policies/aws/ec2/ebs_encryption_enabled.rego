# METADATA
# title :"EBS Encryption Enabled"
# description: "Ensures EBS volumes are encrypted at rest"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-encryption-enabled 
#   recommended_action: "Enable encryption for EBS volumes."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var targetEncryptionLevel = encryptionLevelMap[settings.ebs_encryption_level || this.settings.ebs_encryption_level.default];
#
#        async.each(regions.ec2, function(region, rcb) {
#            var describeVolumes = helpers.addSource(cache, source, ['ec2', 'describeVolumes', region]);
#
#            if (!describeVolumes) return rcb();
#            if (describeVolumes.err || !describeVolumes.data) {
#                helpers.addResult(results, 3, 'Unable to query for EBS volumes: ' + helpers.addError(describeVolumes), region);
#                return rcb();
#            }
#            if (!describeVolumes.data.length) {
#                helpers.addResult(results, 0, 'No EBS volumes present', region);
#                return rcb();
#            }
#
#            for (let volume of describeVolumes.data) {
#                var resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;
#                if (!volume.Encrypted || !volume.KmsKeyId){
#                    helpers.addResult(results, 2, 'EBS volume is unencrypted', region, resource);
#                    continue;
#                }
#
#                var kmsKeyId = volume.KmsKeyId.split('/')[1];
#                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3, 'Could not describe KMS key', region, volume.KmsKeyId);
#                    continue;
#                }
#
#                var encryptionLevel = getEncryptionLevel(describeKey.data.KeyMetadata);
#
#                if (encryptionLevel < targetEncryptionLevel) {
#                    helpers.addResult(results, 1,
#                        `EBS volume is not encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        `EBS volume is encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`,
#                        region, resource);
#                }
#            }
#
#          
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }