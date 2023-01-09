# METADATA
# title :"MQ Auto Minor Version Upgrade"
# description: "Ensure that Amazon MQ brokers have the Auto Minor Version Upgrade feature enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MQ
#   severity: LOW
#   short_code: mq-auto-minor-version-upgrade 
#   recommended_action: "Enabled Auto Minor Version Upgrade feature for MQ brokers"
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
#                var describeBroker = helpers.addSource(cache, source,
#                    ['mq', 'describeBroker', region, broker.BrokerId]);
#                
#                if (!describeBroker || describeBroker.err || !describeBroker.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get brokers description: ${helpers.addError(describeBroker)}`,
#                        region, resource);
#                } else {
#                    if (describeBroker.data.AutoMinorVersionUpgrade) {
#                        helpers.addResult(results, 0, 'Broker has auto minor version upgrade enabled',
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2, 'Broker does not have auto minor version upgrade enabled',
#                            region, resource);
#                    }
#                }
#            }
#
#            rcb();  
#        }, function(){
#            callback(null, results, source);
#        });
#    }