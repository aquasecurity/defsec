# METADATA
# title :"App-Tier Launch Configurations IAM Roles"
# description: "Ensures that App-Tier Auto Scaling launch configuration is configured to use a customer created IAM role."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: app-tier-iam-role 
#   recommended_action: "Update App-Tier Auto Scaling launch configuration and attach a customer created App-Tier IAM role"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var app_tier_tag_key = settings.app_tier_tag_key || this.settings.app_tier_tag_key.default;
#
#        if (!app_tier_tag_key.length) return callback();
#
#        async.each(regions.autoscaling, function(region, rcb){
#            var describeAutoScalingGroups = helpers.addSource(cache, source,
#                ['autoscaling', 'describeAutoScalingGroups', region]);
#
#            var describeLaunchConfigurations = helpers.addSource(cache, source,
#                ['autoscaling', 'describeLaunchConfigurations', region]);
#
#            if (!describeAutoScalingGroups) return rcb();
#
#            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Auto Scaling groups: ${helpers.addError(describeAutoScalingGroups)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups.data.length) {
#                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
#                return rcb();
#            }
#
#            if (!describeLaunchConfigurations || describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Auto Scaling group launch configurations: ${helpers.addError(describeLaunchConfigurations)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeLaunchConfigurations.data.length) {
#                helpers.addResult(results, 0, 'No Auto Scaling launch configurations found', region);
#                return rcb();
#            }
#
#            var launchConfigurations = {};
#            describeLaunchConfigurations.data.forEach(config => {
#                if (!config.IamInstanceProfile) return;
#
#                launchConfigurations[config.LaunchConfigurationName] = config.IamInstanceProfile;
#            });
#
#            var launchConfigurationAsgFound = false;
#            var appTierAsgFound = false;
#
#            for (var g in describeAutoScalingGroups.data) {
#                var asg = describeAutoScalingGroups.data[g];
#
#                if (!asg.AutoScalingGroupARN) continue;
#
#                var resource = asg.AutoScalingGroupARN;
#
#                if (asg.LaunchConfigurationName && asg.LaunchConfigurationName.length){
#                    launchConfigurationAsgFound = true;
#
#                    if (asg.Tags && asg.Tags.length) {
#                        var appTierTag = false;
#
#                        for (var t in asg.Tags) {
#                            var tag = asg.Tags[t];
#
#                            if (tag.Key === app_tier_tag_key) {
#                                appTierTag = true;
#                                appTierAsgFound = true;
#                                break;
#                            }
#                        }
#
#                        if (appTierTag) {
#                            if (launchConfigurations[asg.LaunchConfigurationName]) {
#                                helpers.addResult(results, 0,
#                                    `Launch configuration for App-Tier group "${asg.AutoScalingGroupName}" has customer created IAM role configured`,
#                                    region, resource);
#                            } else {
#                                helpers.addResult(results, 2,
#                                    `Launch configuration for App-Tier group "${asg.AutoScalingGroupName}" does not have customer created IAM role configured`,
#                                    region, resource);
#                            }
#                        }
#                    }
#                }
#            }
#
#            if (!launchConfigurationAsgFound) {
#                helpers.addResult(results, 0,
#                    'No Auto Scaling groups utilizing launch configurations found', region);
#                return rcb();
#            }
#
#            if (!appTierAsgFound) {
#                helpers.addResult(results, 0,
#                    'No App-Tier Auto Scaling groups with found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }