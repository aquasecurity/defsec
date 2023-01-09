# METADATA
# title :"ASG Multiple AZ"
# description: "Ensures that ASGs are created to be cross-AZ for high availability."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/autoscaling/latest/userguide/AutoScalingGroup.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: asg-multi-az 
#   recommended_action: "Modify the autoscaling instance to enable scaling across multiple availability zones."
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
#                    'Unable to query for auto scaling groups: ' + 
#                    helpers.addError(describeAutoScalingGroups), region);
#                return rcb();
#            }
#
#            if (!describeAutoScalingGroups.data.length) {
#                helpers.addResult(results, 0, 'No auto scaling groups found', region);
#                return rcb();
#            }
#
#            // loop through autoscaling Instances
#            describeAutoScalingGroups.data.forEach(function(Asg){
#                var resource = Asg.AutoScalingGroupARN;
#                if (Asg.AvailabilityZones.length <=1) {
#                    helpers.addResult(results, 2,
#                        'Auto scaling group is only using ' + Asg.AvailabilityZones.length +
#                        ' availability zones',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Auto scaling group using ' + Asg.AvailabilityZones.length +
#                        ' availability zones',
#                        region, resource);
#                }
#            });
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }