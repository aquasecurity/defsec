# METADATA
# title :"Config Service Enabled"
# description: "Ensures the AWS Config Service is enabled to detect changes to account resources"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/config/details/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ConfigService
#   severity: LOW
#   short_code: config-service-enabled 
#   recommended_action: "Enable the AWS Config Service for all regions and resources in an account. Ensure that it is properly recording and delivering logs."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var globalServicesMonitored = false;
#
#        async.each(regions.configservice, function(region, rcb){
#            var describeConfigurationRecorders = helpers.addSource(cache, source,
#                ['configservice', 'describeConfigurationRecorders', region]);
#
#            var describeConfigurationRecorderStatus = helpers.addSource(cache, source,
#                ['configservice', 'describeConfigurationRecorderStatus', region]);
#
#            if (describeConfigurationRecorders &&
#                describeConfigurationRecorders.data &&
#                describeConfigurationRecorders.data &&
#                describeConfigurationRecorders.data[0] &&
#                describeConfigurationRecorders.data[0].recordingGroup &&
#                describeConfigurationRecorders.data[0].recordingGroup.includeGlobalResourceTypes) {
#                globalServicesMonitored = true;
#            }
#
#            if (!describeConfigurationRecorders) return rcb();
#
#            // TODO: loop through ALL config recorders
#            // TODO: add resource ARN for config recorders
#
#            if (!describeConfigurationRecorderStatus ||
#                describeConfigurationRecorderStatus.err ||
#                !describeConfigurationRecorderStatus.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Config Service status: ' + helpers.addError(describeConfigurationRecorderStatus), region);
#                return rcb();
#            }
#
#            if (describeConfigurationRecorderStatus.data[0]) {
#                var crs = describeConfigurationRecorderStatus.data[0];
#
#                if (crs.recording) {
#                    if (crs.lastStatus &&
#                        (crs.lastStatus.toUpperCase() == 'SUCCESS' ||
#                         crs.lastStatus.toUpperCase() == 'PENDING')) {
#                        helpers.addResult(results, 0,
#                            'Config Service is configured, recording, and delivering properly', region);
#                    } else {
#                        helpers.addResult(results, 1,
#                            'Config Service is configured, and recording, but not delivering properly', region);
#                    }
#                } else {
#                    helpers.addResult(results, 2, 'Config Service is configured but not recording', region);
#                }
#
#                return rcb();
#            }
#
#            helpers.addResult(results, 2, 'Config Service is not configured', region);
#
#            rcb();
#        }, function(){
#            if (!globalServicesMonitored) {
#                helpers.addResult(results, 2, 'Config Service is not monitoring global services');
#            } else {
#                helpers.addResult(results, 0, 'Config Service is monitoring global services');
#            }
#
#            callback(null, results, source);
#        });
#    }