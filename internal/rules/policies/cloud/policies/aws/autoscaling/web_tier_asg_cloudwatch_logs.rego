# METADATA
# title :"Web-Tier Auto Scaling Group CloudWatch Logs Enabled"
# description: "Ensures that Web-Tier Auto Scaling Groups are using CloudWatch Logs agent."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: web-tier-asg-cloudwatch-logs 
#   recommended_action: "Update web-tier Auto Scaling Group to use CloudWatch Logs agent"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            web_tier_tag_key: settings.web_tier_tag_key || this.settings.web_tier_tag_key.default,
#            cw_log_agent_install_command: settings.cw_log_agent_install_command || this.settings.cw_log_agent_install_command.default,
#            s3_cw_agent_config_file: settings.s3_cw_agent_config_file || this.settings.s3_cw_agent_config_file.default
#        };
#
#        if (!config.web_tier_tag_key.length) return callback();
#
#        async.each(regions.autoscaling, function(region, rcb){
#            var describeAutoScalingGroups = helpers.addSource(cache, source,
#                ['autoscaling', 'describeAutoScalingGroups', region]);
#
#            if (!describeAutoScalingGroups) return rcb();
#
#            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for auto scaling groups: ${helpers.addError(describeAutoScalingGroups)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups.data.length) {
#                helpers.addResult(results, 0, 'No auto scaling groups found', region);
#                return rcb();
#            }
#
#            var webTierAsgFound = false;
#            async.each(describeAutoScalingGroups.data, function(asg, cb){
#
#                var webTierTag = false;
#                if (asg.Tags && asg.Tags.length){
#                    for (var t in asg.Tags) {
#                        var tag = asg.Tags[t];
#                        if (tag && tag.Key && tag.Key === config.web_tier_tag_key) {
#                            webTierTag = true;
#                            webTierAsgFound = true;
#                            break;
#                        }
#                    }
#                }
#
#                if (webTierTag) {
#                    var resource = asg.AutoScalingGroupARN;
#
#                    var describeLaunchConfigurations = helpers.addSource(cache, source,
#                        ['autoscaling', 'describeLaunchConfigurations', region, asg.AutoScalingGroupARN]);
#
#                    if (!describeLaunchConfigurations ||
#                        describeLaunchConfigurations.err ||
#                        !describeLaunchConfigurations.data ||
#                        !describeLaunchConfigurations.data.LaunchConfigurations ||
#                        !describeLaunchConfigurations.data.LaunchConfigurations.length) {
#                        helpers.addResult(results, 3,
#                            `Unable to query launch configurations for auto scaling group "${asg.AutoScalingGroupName}": ${helpers.addError(describeLaunchConfigurations)}`,
#                            region, resource);
#                        return cb();
#                    }
#
#                    var logsEnabled = false;                    
#                    describeLaunchConfigurations.data.LaunchConfigurations.forEach(function(launchConfig){
#                        
#                        config.cw_log_agent_install_command = config.cw_log_agent_install_command.replace('<AWS_REGION>', region);
#                        config.cw_log_agent_install_command = config.cw_log_agent_install_command.replace('<S3_CLOUDWATCH_AGENT_CONFIG_FILE_LOCATION>', config.s3_cw_agent_config_file);
#                        if (launchConfig.UserData &&
#                            launchConfig.UserData.indexOf(config.cw_log_agent_install_command) > -1) {
#                            logsEnabled = true;
#                        }
#                    });
#
#                    if (logsEnabled) {
#                        helpers.addResult(results, 0,
#                            `Auto scaling group "${asg.AutoScalingGroupName}" has CloudWatch logs enabled`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Auto scaling group "${asg.AutoScalingGroupName}" does not have CloudWatch logs enabled`,
#                            region, resource);
#                    }
#                }
#
#                if (!webTierAsgFound) {
#                    helpers.addResult(results, 0,
#                        'No Web-Tier auto scaling groups found', region);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#
#        }, function(){
#            callback(null, results, source);
#        });
#
#    }