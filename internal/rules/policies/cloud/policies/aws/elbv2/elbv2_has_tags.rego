# METADATA
# title :"ELBv2 Has Tags"
# description: "Ensure that ELBv2 load balancers have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ELBv2
#   severity: LOW
#   short_code: elbv2-has-tags 
#   recommended_action: "Modify ELBv2 and add tags."
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
#                    'Unable to query for Application/Network load balancers: ' + helpers.addError(describeLoadBalancers), region);
#                return rcb();
#            }
#
#            if (!describeLoadBalancers.data.length) {
#                helpers.addResult(results, 0, 'No Application/Network load balancers found', region);
#                return rcb();
#            }
#            const arnList = [];
#            for (let lb of describeLoadBalancers.data){
#                arnList.push(lb.LoadBalancerArn);
#            }
#            helpers.checkTags(cache, 'ElasticLoadbalancing', arnList, region, results);
#            return rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }