# METADATA
# title :"Connect Customer Profiles Domain Encrypted"
# description: "Ensure that AWS Connect Customer Profiles domains are using desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/connect/latest/adminguide/enable-customer-profiles.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Connect
#   severity: LOW
#   short_code: customer-profiles-domain-encrypted 
#   recommended_action: "Enabled data encryption feature for Connect Customer Profiles"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var defaultRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);
#
#        var config = {
#            desiredEncryptionLevelString: settings.customer_profiles_desired_encryption_level || this.settings.customer_profiles_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.customerprofiles, function(region, rcb){        
#            var listDomains = helpers.addSource(cache, source,
#                ['customerprofiles', 'listDomains', region]);
#
#            if (!listDomains) return rcb();
#
#            if (listDomains.err || !listDomains.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query customerprofiles domain: ' + helpers.addError(listDomains), region);
#                return rcb();
#            }
#
#            if (!listDomains.data.length) {
#                helpers.addResult(results, 0, 'No customerprofiles domain found', region);
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
#            for (let domain of listDomains.data) {
#                if (!domain.DomainName) continue;
#
#                let resource = `arn:${awsOrGov}:profile:${region}:${accountId}:domain/${domain.DomainName}`;
#
#                var getDomain = helpers.addSource(cache, source,
#                    ['customerprofiles', 'getDomain', region, domain.DomainName]);
#
#                if (!getDomain || getDomain.err || !getDomain.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get customerprofiles domain description: ${helpers.addError(getDomain)}`,
#                        region, resource);
#                    continue;
#                } 
#
#                if (getDomain.data.DefaultEncryptionKey) {
#                    let DefaultEncryptionKey = getDomain.data.DefaultEncryptionKey;
#                    var keyId = DefaultEncryptionKey.split('/')[1] ? DefaultEncryptionKey.split('/')[1] : DefaultEncryptionKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, DefaultEncryptionKey);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                } else {
#                    helpers.addResult(results, 3,
#                        'Unable to find Customer Profile domain encryption key', region, resource);
#                    continue;
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Customer Profile domain is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Customer Profile domain is encrypted with ${currentEncryptionLevelString} \
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