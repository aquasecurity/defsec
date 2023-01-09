# METADATA
# title :"Auto Scaling Group Cooldown Period"
# description: "Ensure that your AWS Auto Scaling Groups are configured to use a cool down period."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: asg-cooldown-period 
#   recommended_action: "Implement proper cool down period for Auto Scaling groups to temporarily suspend any scaling actions."
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
#            if (!describeAutoScalingGroups) return rcb();
#
#            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Auto Scaling groups: ' + 
#                    helpers.addError(describeAutoScalingGroups), region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups.data.length) {
#                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
#                return rcb();
#            }
#
#            for (let group of describeAutoScalingGroups.data){
#                if (!group.AutoScalingGroupARN) continue;
#
#                let resource = group.AutoScalingGroupARN;
#                
#                if (group.DefaultCooldown) {
#                    helpers.addResult(results, 0,
#                        'Auto Scaling group has cool down period configured',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Auto Scaling group does not have cool down period configured',
#                        region, resource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }