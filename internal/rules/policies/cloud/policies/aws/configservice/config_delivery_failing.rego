# METADATA
# title :"Config Delivery Failing"
# description: "Ensure that the AWS Config log files are delivered to the S3 bucket in order to store logging data for auditing purposes without any failures."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ConfigService
#   severity: LOW
#   short_code: config-delivery-failing 
#   recommended_action: "Configure AWS Config log files to be delivered without any failures to designated S3 bucket."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        
#        async.each(regions.configservice, function(region, rcb){
#            var describeConfigurationRecorderStatus = helpers.addSource(cache, source,
#                ['configservice', 'describeConfigurationRecorderStatus', region]);
#
#            if (!describeConfigurationRecorderStatus) return rcb();
#
#            if (describeConfigurationRecorderStatus.err || !describeConfigurationRecorderStatus.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Config Service configuration recorder statuses: ' + helpers.addError(describeConfigurationRecorderStatus), region);
#                return rcb();
#            }
#
#            if (!describeConfigurationRecorderStatus.data.length) {
#                helpers.addResult(results, 0,
#                    'No Config Service configuration recorder statuses found', region);
#                return rcb();
#            }
#
#            if (describeConfigurationRecorderStatus.data[0].lastStatus &&
#                describeConfigurationRecorderStatus.data[0].lastStatus.toUpperCase() === 'SUCCESS') {
#                helpers.addResult(results, 0,
#                    'AWS Config service is delivering log files to the designated recipient successfully',
#                    region);
#            } else {
#                helpers.addResult(results, 2,
#                    'AWS Config service is not delivering log files to the designated recipient successfully',
#                    region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }