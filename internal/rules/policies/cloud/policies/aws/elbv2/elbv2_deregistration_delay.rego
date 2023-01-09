# METADATA
# title :"ELBv2 Deregistration Delay"
# description: "Ensures that AWS ELBv2 target groups have deregistration delay configured."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#deregistration-delay
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELBv2
#   severity: LOW
#   short_code: elbv2-deregistration-delay 
#   recommended_action: "Update ELBv2 target group attributes and set the deregistration delay value"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elbv2, function(region, rcb){
#            var describeTargetGroups = helpers.addSource(cache, source,
#                ['elbv2', 'describeTargetGroups', region]);
#
#            if (!describeTargetGroups) return rcb();
#
#            if (describeTargetGroups.err || !describeTargetGroups.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Application/Network load balancer target groups: ${helpers.addError(describeTargetGroups)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeTargetGroups.data.length) {
#                helpers.addResult(results, 0,
#                    'No Application/Network load balancer target groups found', region);
#                return rcb();
#            }
#
#            async.each(describeTargetGroups.data, function(targetGroup, tcb){
#                var resource = targetGroup.TargetGroupArn;
#                var describeTargetGroupAttributes = helpers.addSource(cache, source,
#                    ['elbv2', 'describeTargetGroupAttributes', region, resource]);
#
#                if (!describeTargetGroupAttributes || describeTargetGroupAttributes.err || !describeTargetGroupAttributes.data
#                        || !describeTargetGroupAttributes.data.Attributes) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for Application/Network load balancer target group attributes: ${helpers.addError(describeTargetGroupAttributes)}`,
#                        region, resource);
#                    return tcb();
#                }
#
#                var deregistationDelayConfigured = false;
#
#                if (describeTargetGroupAttributes.data.Attributes.length) {
#                    for (var attribute of describeTargetGroupAttributes.data.Attributes) {
#                        if (attribute.Key && attribute.Key === 'deregistration_delay.timeout_seconds' &&
#                            attribute.Value && parseInt(attribute.Value) > 0) {
#                            deregistationDelayConfigured = true;
#                            break;
#                        }
#                    }
#                }
#
#                if (deregistationDelayConfigured) {
#                    helpers.addResult(results, 0,
#                        `Application/Network load balancer target group "${targetGroup.TargetGroupName}" has deregistration delay configured`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Application/Network load balancer target group "${targetGroup.TargetGroupName}" does not have deregistration delay configured`,
#                        region, resource);
#                }
#
#                tcb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }