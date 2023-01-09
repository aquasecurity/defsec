# METADATA
# title :"MQ Deployment Mode"
# description: "Ensure that for high availability, your AWS MQ brokers are using the active/standby deployment mode instead of single-instance "
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/active-standby-broker-deployment.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MQ
#   severity: LOW
#   short_code: mq-deployment-mode 
#   recommended_action: "Enabled Deployment Mode feature for MQ brokers"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.mq, function(region, rcb){        
#            var listBrokers = helpers.addSource(cache, source,
#                ['mq', 'listBrokers', region]);
#
#            if (!listBrokers) return rcb();
#
#            if (listBrokers.err || !listBrokers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query MQ brokers: ' + helpers.addError(listBrokers), region);
#                return rcb();
#            }
#
#            if (!listBrokers.data.length) {
#                helpers.addResult(results, 0, 'No MQ brokers found', region);
#                return rcb();
#            }
#            
#            for (let broker of listBrokers.data) {
#                if (!broker.BrokerArn) continue;
#               
#                let resource = broker.BrokerArn;
#
#                if (broker.DeploymentMode && broker.DeploymentMode.toUpperCase() === 'ACTIVE_STANDBY_MULTI_AZ') {
#                    helpers.addResult(results, 0, 'Broker has active/standby deployment mode enabled',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2, 'Broker does not have active/standby deployment mode enabled',
#                        region, resource);
#                }
#            }
#            rcb();  
#        }, function(){
#            callback(null, results, source);
#        });
#    }