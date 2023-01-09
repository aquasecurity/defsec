# METADATA
# title :"EC2 Max Instances"
# description: "Ensures the total number of EC2 instances does not exceed a set threshold."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: instance-max-count 
#   recommended_action: "Ensure that the number of running EC2 instances matches the expected count. If instances are launched above the threshold, investigate to ensure they are legitimate."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold.default,
#            instance_count_region_threshold_us_east_1: settings.instance_count_region_threshold_us_east_1 || this.settings.instance_count_region_threshold_us_east_1.default,
#            instance_count_region_threshold_us_east_2: settings.instance_count_region_threshold_us_east_2 || this.settings.instance_count_region_threshold_us_east_2.default,
#            instance_count_region_threshold_us_west_1: settings.instance_count_region_threshold_us_west_1 || this.settings.instance_count_region_threshold_us_west_1.default,
#            instance_count_region_threshold_us_west_2: settings.instance_count_region_threshold_us_west_2 || this.settings.instance_count_region_threshold_us_west_2.default,
#            instance_count_region_threshold_ap_northeast_1: settings.instance_count_region_threshold_ap_northeast_1 || this.settings.instance_count_region_threshold_ap_northeast_1.default,
#            instance_count_region_threshold_ap_northeast_2: settings.instance_count_region_threshold_ap_northeast_2 || this.settings.instance_count_region_threshold_ap_northeast_2.default,
#            instance_count_region_threshold_ap_northeast_3: settings.instance_count_region_threshold_ap_northeast_3 || this.settings.instance_count_region_threshold_ap_northeast_3.default,
#            instance_count_region_threshold_ap_southeast_1: settings.instance_count_region_threshold_ap_southeast_1 || this.settings.instance_count_region_threshold_ap_southeast_1.default,
#            instance_count_region_threshold_ap_southeast_2: settings.instance_count_region_threshold_ap_southeast_2 || this.settings.instance_count_region_threshold_ap_southeast_2.default,
#            instance_count_region_threshold_ap_southeast_3: settings.instance_count_region_threshold_ap_southeast_3 || this.settings.instance_count_region_threshold_ap_southeast_3.default,
#            instance_count_region_threshold_eu_central_1: settings.instance_count_region_threshold_eu_central_1 || this.settings.instance_count_region_threshold_eu_central_1.default,
#            instance_count_region_threshold_eu_west_1: settings.instance_count_region_threshold_eu_west_1 || this.settings.instance_count_region_threshold_eu_west_1.default,
#            instance_count_region_threshold_eu_west_2: settings.instance_count_region_threshold_eu_west_2 || this.settings.instance_count_region_threshold_eu_west_2.default,
#            instance_count_region_threshold_eu_west_3: settings.instance_count_region_threshold_eu_west_3 || this.settings.instance_count_region_threshold_eu_west_3.default,
#            instance_count_region_threshold_eu_north_1: settings.instance_count_region_threshold_eu_north_1 || this.settings.instance_count_region_threshold_eu_north_1.default,
#            instance_count_region_threshold_eu_south_1: settings.instance_count_region_threshold_eu_south_1 || this.settings.instance_count_region_threshold_eu_south_1.default,
#            instance_count_region_threshold_sa_east_1: settings.instance_count_region_threshold_sa_east_1 || this.settings.instance_count_region_threshold_sa_east_1.default,
#            instance_count_region_threshold_ap_south_1: settings.instance_count_region_threshold_ap_south_1 || this.settings.instance_count_region_threshold_ap_south_1.default,
#            instance_count_region_threshold_ap_east_1: settings.instance_count_region_threshold_ap_east_1 || this.settings.instance_count_region_threshold_ap_east_1.default,
#            instance_count_region_threshold_ca_central_1: settings.instance_count_region_threshold_ca_central_1 || this.settings.instance_count_region_threshold_ca_central_1.default,
#            instance_count_region_threshold_me_south_1: settings.instance_count_region_threshold_me_south_1 || this.settings.instance_count_region_threshold_me_south_1.default,
#            instance_count_region_threshold_me_central_1: settings.instance_count_region_threshold_me_central_1 || this.settings.instance_count_region_threshold_me_central_1.default,
#            instance_count_region_threshold_af_south_1: settings.instance_count_region_threshold_af_south_1 || this.settings.instance_count_region_threshold_af_south_1.default,
#            instance_count_region_threshold_us_gov_west_1: settings.instance_count_region_threshold_us_gov_west_1 || this.settings.instance_count_region_threshold_us_gov_west_1.default,
#            instance_count_region_threshold_us_gov_east_1: settings.instance_count_region_threshold_us_gov_east_1 || this.settings.instance_count_region_threshold_us_gov_east_1.default,
#            instance_count_region_threshold_cn_north_1: settings.instance_count_region_threshold_cn_north_1 || this.settings.instance_count_region_threshold_cn_north_1.default,
#            instance_count_region_threshold_cn_northwest_1: settings.instance_count_region_threshold_cn_northwest_1 || this.settings.instance_count_region_threshold_cn_northwest_1.default
#        };
#
#        for (var c in config) {
#            if (Object.prototype.hasOwnProperty.call(settings, c)) {
#                config[c] = settings[c];    
#            }
#        }
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var instanceCountGlobal = 0;
#
#        async.each(regions.ec2, function(region, rcb){
#
#            var describeInstances = helpers.addSource(cache, source,
#                ['ec2', 'describeInstances', region]);
#
#            if (!describeInstances) return rcb();
#
#            if (describeInstances.err || !describeInstances.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
#                return rcb();
#            }
#
#            if (!describeInstances.data.length) {
#                helpers.addResult(results, 0, 'No instances found', region);
#                return rcb();
#            }
#
#            var instanceCount = 0;
#
#            for (var i in describeInstances.data) {
#                for (var j in describeInstances.data[i].Instances) {
#                    var instance = describeInstances.data[i].Instances[j];
#
#                    if (instance.State.Name == 'running') {
#                        instanceCountGlobal +=1;
#                        instanceCount +=1;
#                    }
#                }
#            }
#
#            // Print region results
#            var regionUnderscore = region.replace(/-/g, '_');
#            var regionThreshold = config['instance_count_region_threshold_'+regionUnderscore];
#
#            if (!regionThreshold) {
#                helpers.addResult(results, 3,
#                    'The region: ' + region + ' does not have a maximum instances count setting.', region);
#            } else if (instanceCount > regionThreshold) {
#                helpers.addResult(results, 2,
#                    instanceCount + ' EC2 instances running in ' +
#                    region + ' region, exceeding limit of: ' +
#                    regionThreshold, region, null, custom);
#            } else {
#                helpers.addResult(results, 0,
#                    instanceCount + ' instances in the region are within the regional expected count of: ' + regionThreshold, region, null, custom);
#            }
#
#            rcb();
#        });
#
#        // Print global results
#        var globalThreshold = config.instance_count_global_threshold;
#
#        if (instanceCountGlobal > globalThreshold) {
#            helpers.addResult(results, 2,
#                instanceCountGlobal + ' EC2 instances running in all regions, exceeding limit of: ' + globalThreshold, null, null, custom);
#        } else {
#            helpers.addResult(results, 0,
#                instanceCountGlobal + ' instances in the account are within the global expected count of: ' + globalThreshold, null, null, custom);
#        }
#
#        callback(null, results, source);
#    }