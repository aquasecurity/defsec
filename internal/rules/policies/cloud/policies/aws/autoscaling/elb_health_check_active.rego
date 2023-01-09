# METADATA
# title :"ELB Health Check Active"
# description: "Ensures all Auto Scaling groups have ELB health check active."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: elb-health-check-active 
#   recommended_action: "Enable ELB health check for the Auto Scaling groups."
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
#                    `Unable to query for Auto Scaling groups: ${helpers.addError(describeAutoScalingGroups)}`, region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups.data.length) {
#                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
#                return rcb();
#            }
#
#            describeAutoScalingGroups.data.forEach(function(asg){
#                if (!asg.AutoScalingGroupARN) return;
#
#                var resource = asg.AutoScalingGroupARN;
#
#                if (asg.HealthCheckType && asg.HealthCheckType === 'ELB') {
#                    helpers.addResult(results, 0,
#                        `Auto Scaling group "${asg.AutoScalingGroupName}" has ELB health check active`,
#                        region, resource);
#                } else if (!asg.LoadBalancerNames || !asg.LoadBalancerNames.length) {
#                    helpers.addResult(results, 0,
#                        `Auto Scaling group "${asg.AutoScalingGroupName}" does not use ELBs`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Auto Scaling group "${asg.AutoScalingGroupName}" does not have ELB health check active`,
#                        region, resource);
#                }
#            });
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }