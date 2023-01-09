# METADATA
# title :"Empty AutoScaling Group"
# description: "Ensures all autoscaling groups contain at least 1 instance."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/AutoScalingGroup.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:AutoScaling
#   severity: LOW
#   short_code: empty-a-s-g 
#   recommended_action: "Delete the unused AutoScaling group."
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
#            describeAutoScalingGroups.data.forEach(function(asg){
#                var resource = asg.AutoScalingGroupARN;
#                if (!asg.Instances || !asg.Instances.length) {
#                    helpers.addResult(results, 2,
#                        'Auto scaling group: ' + asg.AutoScalingGroupName + ' does not contain any instance',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Auto scaling group: ' + asg.AutoScalingGroupName + ' contains ' + asg.Instances.length + ' instance(s)',
#                        region, resource);
#                }
#            });
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }