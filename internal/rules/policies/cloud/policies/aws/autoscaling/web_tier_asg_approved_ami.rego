# METADATA
# title :"Web-Tier ASG Launch Configurations Approved AMIs"
# description: "Ensures that Web-Tier Auto Scaling Group Launch Configurations are using approved AMIs."
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
#   short_code: web-tier-asg-approved-ami 
#   recommended_action: "Update Web-Tier ASG Launch Configuration to use approved AMIs only"
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
#            approved_amis: settings.approved_amis || this.settings.approved_amis.default
#        };
#
#        if (!config.web_tier_tag_key.length) return callback(null, results, source);
#
#        config.approved_amis = config.approved_amis.split(',');
#
#        async.each(regions.autoscaling, function(region, rcb){
#            var describeAutoScalingGroups = helpers.addSource(cache, source,
#                ['autoscaling', 'describeAutoScalingGroups', region]);
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
#            var webTierAsgFound = false;
#            async.each(describeAutoScalingGroups.data, function(asg, cb){
#                var webTierTagFound = false;
#                if (asg.Tags && asg.Tags.length){
#                    for (var t in asg.Tags) {
#                        var tag = asg.Tags[t];
#                        if (tag && tag.Key && tag.Key === config.web_tier_tag_key) {
#                            webTierTagFound = true;
#                            webTierAsgFound = true;
#                            break;
#                        }
#                    }
#                }
#
#                if (webTierTagFound) {
#                    var resource = asg.AutoScalingGroupARN;
#                    var describeLaunchConfigurations = helpers.addSource(cache, source,
#                        ['autoscaling', 'describeLaunchConfigurations', region, asg.AutoScalingGroupARN]);
#
#                    var imageFound = false;
#                    var unapprovedAmis = [];
#
#                    if (!describeLaunchConfigurations ||
#                        describeLaunchConfigurations.err ||
#                        !describeLaunchConfigurations.data ||
#                        !describeLaunchConfigurations.data.LaunchConfigurations ||
#                        !describeLaunchConfigurations.data.LaunchConfigurations.length) {
#                        helpers.addResult(results, 3,
#                            `Unable to query launch configurations for Auto Scaling group "${asg.AutoScalingGroupName}": ${helpers.addError(describeLaunchConfigurations)}`,
#                            region, resource);
#                        return cb();
#                    }
#
#                    describeLaunchConfigurations.data.LaunchConfigurations.forEach(function(launchConfig){
#                        if (launchConfig.ImageId) {
#                            imageFound = true;
#                            if (config.approved_amis.indexOf(launchConfig.ImageId) === -1){
#                                unapprovedAmis.push(launchConfig.ImageId);
#                            }
#                        }
#                    });
#
#                    if (imageFound) {
#                        if (!unapprovedAmis.length) {
#                            helpers.addResult(results, 0,
#                                `Launch Configuration for Web-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is using approved AMIs`,
#                                region, resource);
#                        } else {
#                            helpers.addResult(results, 2,
#                                `Launch Configuration for Web-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is using these unapproved AMIs: ${unapprovedAmis.join(', ')}`,
#                                region, resource);
#                        }
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Launch Configuration for Web-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is not using any AMI`,
#                            region, resource);
#                    }
#                }
#
#                if (!webTierAsgFound) {
#                    helpers.addResult(results, 0,
#                        'No Web-Tier Auto Scaling groups found', region);
#                }
#
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