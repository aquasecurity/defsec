# METADATA
# title :"ELB No Instances"
# description: "Detects ELBs that have no backend instances attached"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-backend-instances.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELB
#   severity: LOW
#   short_code: elb-no-instances 
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
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.elb, function(region, rcb){
#            var describeLoadBalancers = helpers.addSource(cache, source,
#                ['elb', 'describeLoadBalancers', region]);
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
#                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
#                var elbArn = 'arn:aws:elasticloadbalancing:' +
#                              region + ':' + accountId + ':' +
#                              'loadbalancer/' + lb.LoadBalancerName;
#
#                if (lb.Instances.length) {
#                    helpers.addResult(results, 0, 'ELB has ' + lb.Instances.length + ' backend instances', region, elbArn);
#                } else {
#                    helpers.addResult(results, 2, 'ELB does not have backend instances', region, elbArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }