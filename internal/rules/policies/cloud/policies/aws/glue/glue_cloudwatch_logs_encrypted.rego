# METADATA
# title :"AWS Glue CloudWatch Encrypted Logs"
# description: "Ensures that encryption at-rest is enabled when writing AWS Glue logs to Amazon CloudWatch."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AWS Glue
#   severity: LOW
#   short_code: glue-cloudwatch-logs-encrypted 
#   recommended_action: "Modify Glue Security Configurations to enable CloudWatch logs encryption at-rest"
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
#                    `Unable to query for Glue security configurations: ${helpers.addError(getSecurityConfigurations)}`, region);
#                return rcb();
#            }
#
#            if (!getSecurityConfigurations.data.length) {
#                helpers.addResult(results, 0,
#                    'No Glue security configurations found', region);
#                return rcb();
#            }
#
#            getSecurityConfigurations.data.forEach(configuration => {
#                if (!configuration.Name) return;
#
#                var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/securityConfiguration/${configuration.Name}`;
#
#                if (configuration.EncryptionConfiguration &&
#                    configuration.EncryptionConfiguration.CloudWatchEncryption &&
#                    configuration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode &&
#                    configuration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode === 'SSE-KMS') {
#                    helpers.addResult(results, 0,
#                        `Glue Security Configuration "${configuration.Name}" has CloudWatch logs encryption enabled`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Glue Security Configuration "${configuration.Name}" has CloudWatch logs encryption disabled`,
#                        region, resource);
#                }
#
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }