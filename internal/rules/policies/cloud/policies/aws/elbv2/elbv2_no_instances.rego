# METADATA
# title :"ELBv2 No Instances"
# description: "Detects ELBs that have no target groups attached"
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
#   short_code: elbv2-no-instances 
#   recommended_action: "Delete old ELBs that no longer have backend resources."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elb, function(region, rcb){
#            var describeLoadBalancers = helpers.addSource(cache, source,
#                ['elbv2', 'describeLoadBalancers', region]);
#
#            if (!describeLoadBalancers) return rcb();
#
#            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
#                return rcb();
#            }
#
#            if (!describeLoadBalancers.data.length) {
#                helpers.addResult(results, 0, 'No load balancers present', region);
#                return rcb();
#            }
#
#            async.each(describeLoadBalancers.data, function(lb, cb){
#                var describeTargetGroups = helpers.addSource(cache, source,
#                    ['elbv2', 'describeTargetGroups', region, lb.DNSName]);
#
#                var elbArn = lb.LoadBalancerArn;
#                if (describeTargetGroups && describeTargetGroups.data && describeTargetGroups.data.TargetGroups && describeTargetGroups.data.TargetGroups.length){
#                    helpers.addResult(results, 0,
#                        'ELB has ' + describeTargetGroups.data.TargetGroups.length + ' target groups', region, elbArn);
#                } else {
#                    helpers.addResult(results, 2, 'ELB does not have target groups ', region, elbArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }