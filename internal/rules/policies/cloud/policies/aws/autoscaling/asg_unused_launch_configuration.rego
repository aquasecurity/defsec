# METADATA
# title :"Auto Scaling Unused Launch Configuration"
# description: "Ensure that any unused Auto Scaling Launch Configuration templates are identified and removed from your account in order to adhere to AWS best practices."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: asg-unused-launch-configuration 
#   recommended_action: "Identify and remove any Auto Scaling Launch Configuration templates that are not associated anymore with ASGs available in the selected AWS region."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.autoscaling, function(region, rcb){
#            var describeAutoScalingGroups = helpers.addSource(cache, source,
#                ['autoscaling', 'describeAutoScalingGroups', region]);
#
#            var describeLaunchConfigurations = helpers.addSource(cache, source,
#                ['autoscaling', 'describeLaunchConfigurations', region]);
#    
#            if (!describeLaunchConfigurations) return rcb();
#
#            if (describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Auto Scaling launch configurations: ' + helpers.addError(describeLaunchConfigurations), region);
#                return rcb();
#            }
#
#            if (!describeLaunchConfigurations.data.length) {
#                helpers.addResult(results, 0, 'No Auto Scaling launch configurations found', region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups || describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Auto Scaling groups: ' + helpers.addError(describeAutoScalingGroups), region);
#                return rcb();
#            }
#
#            let usedLaunchConfig = [];
#            describeAutoScalingGroups.data.forEach(group => {
#                if (!group.LaunchConfigurationName) return;
#
#                if (!usedLaunchConfig.includes(group.LaunchConfigurationName)) {
#                    usedLaunchConfig.push(group.LaunchConfigurationName);
#                }
#            });
#
#            describeLaunchConfigurations.data.forEach(config => {
#                if (!config.LaunchConfigurationARN) return;
#
#                if (config.LaunchConfigurationName && usedLaunchConfig.includes(config.LaunchConfigurationName)) {
#                    helpers.addResult(results, 0,
#                        `Auto Scaling launch configuration "${config.LaunchConfigurationName}" is being used`,
#                        region, config.LaunchConfigurationARN);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Auto Scaling launch configuration "${config.LaunchConfigurationName}" is not being used`,
#                        region, config.LaunchConfigurationARN);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }