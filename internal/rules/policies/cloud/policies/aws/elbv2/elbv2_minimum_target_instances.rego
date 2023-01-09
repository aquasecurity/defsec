# METADATA
# title :"ELBv2 Minimum Number of EC2 Target Instances"
# description: "Ensures that there is a minimum number of two healthy target instances associated with each AWS ELBv2 load balancer."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELBv2
#   severity: LOW
#   short_code: elbv2-minimum-target-instances 
#   recommended_action: "Associate at least two healthy target instances to AWS ELBv2 load balancer"
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
#            var describeLoadBalancers = helpers.addSource(cache, source,
#                ['elbv2', 'describeLoadBalancers', region]);
#
#            if (!describeLoadBalancers) return rcb();
#
#            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Application/Network load balancers: ${helpers.addError(describeLoadBalancers)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!describeLoadBalancers.data.length) {
#                helpers.addResult(results, 0,
#                    'No Application/Network load balancers found', region);
#                return rcb();
#            }
#
#            async.each(describeLoadBalancers.data, function(elb, cb){
#                var resource = elb.LoadBalancerArn;
#                var healthyInstances = 0;
#
#                var describeTargetGroups = helpers.addSource(cache, source,
#                    ['elbv2', 'describeTargetGroups', region, elb.DNSName]);
#
#                if (!describeTargetGroups || describeTargetGroups.err || !describeTargetGroups.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for Application/Network load balancer target groups: ${helpers.addError(describeTargetGroups)}`,
#                        region, resource);
#                    return cb();
#                }
#
#                if (!describeTargetGroups.data.TargetGroups || !describeTargetGroups.data.TargetGroups.length){
#                    helpers.addResult(results, 2,
#                        'No Application/Network load balancer target groups found',
#                        region, resource);
#                    return cb();
#                }
#
#                async.each(describeTargetGroups.data.TargetGroups, function(targetGroup, tcb){
#                    var describeTargetHealth = helpers.addSource(cache, source,
#                        ['elbv2', 'describeTargetHealth', region, targetGroup.TargetGroupArn]);
#
#                    if (!describeTargetHealth || describeTargetHealth.err || !describeTargetHealth.data
#                            || !describeTargetHealth.data.TargetHealthDescriptions || !describeTargetHealth.data.TargetHealthDescriptions.length) {
#                        return tcb();
#                    }
#
#                    describeTargetHealth.data.TargetHealthDescriptions.forEach(healthDescription => {
#                        if (healthDescription.Target && healthDescription.Target.Id &&
#                            healthDescription.TargetHealth && healthDescription.TargetHealth.State === 'healthy') {
#                            healthyInstances = healthyInstances + 1;
#                        }
#                    });
#
#                    tcb();
#                });
#
#                if (healthyInstances >= 2) {
#                    helpers.addResult(results, 0,
#                        `Application/Network load balancer has ${healthyInstances} healthy instance(s) associated`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Application/Network load balancer has only ${healthyInstances} healthy instance(s) associated`,
#                        region, resource);
#                }
#
#                cb();
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }