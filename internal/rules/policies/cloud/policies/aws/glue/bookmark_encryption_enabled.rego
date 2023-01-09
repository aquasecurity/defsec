# METADATA
# title :"AWS Glue Job Bookmark Encryption Enabled"
# description: "Ensures that AWS Glue job bookmark encryption is enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Glue
#   severity: LOW
#   short_code: bookmark-encryption-enabled 
#   recommended_action: "Recreate Glue security configurations and enable job bookmark encryption"
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
#
#        async.each(regions.glue, function(region, rcb){
#            var getSecurityConfigurations = helpers.addSource(cache, source,
#                ['glue', 'getSecurityConfigurations', region]);
#
#            if (!getSecurityConfigurations) return rcb();
#
#            if (getSecurityConfigurations.err || !getSecurityConfigurations.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Glue security configurations: ${helpers.addError(getSecurityConfigurations)}`, region);
#                return rcb();
#            }
#
#            if (!getSecurityConfigurations.data.length) {
#                helpers.addResult(results, 0,
#                    'No AWS Glue security configurations found', region);
#                return rcb();
#            }
#
#            for (var configuration of getSecurityConfigurations.data) {
#                if (!configuration.Name) continue;
#
#                var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/securityConfiguration/${configuration.Name}`;
#
#                if (configuration && configuration.EncryptionConfiguration &&
#                    configuration.EncryptionConfiguration.JobBookmarksEncryption &&
#                    configuration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode &&
#                    configuration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode.toUpperCase() !== 'DISABLED') {
#
#                    helpers.addResult(results, 0,
#                        `Glue Security Configuration "${configuration.Name}" has job bookmark encryption enabled`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Glue Security Configuration "${configuration.Name}" does not have job bookmark encryption enabled`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }