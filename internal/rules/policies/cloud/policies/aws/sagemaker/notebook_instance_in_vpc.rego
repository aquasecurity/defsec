# METADATA
# title :"Notebook instance in VPC"
# description: "Ensure that Amazon SageMaker Notebook instances are launched within a VPC."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SageMaker
#   severity: LOW
#   short_code: notebook-instance-in-vpc 
#   recommended_action: "Migrate Notebook instances to exist within a VPC"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.sagemaker, function(region, rcb){
#            var listNotebookInstances = helpers.addSource(cache, source,
#                ['sagemaker', 'listNotebookInstances', region]);
#
#            if (!listNotebookInstances) return rcb();
#
#            if (listNotebookInstances.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Notebook Instances: ' +
#                    helpers.addError(listNotebookInstances), region);
#                return rcb();
#            }
#
#            if (!listNotebookInstances.data || !listNotebookInstances.data.length) {
#                helpers.addResult(
#                    results, 0, 'No Notebook Instances Found', region);
#                return rcb();
#            }
#
#            for (var i in listNotebookInstances.data) {
#                var instance = listNotebookInstances.data[i];
#                var instanceArn = instance.NotebookInstanceArn;
#
#                // A network interface is assigned when the notebook is VPC-based.
#                // Similarly, the instance must be assigned to a subnet if it is VPC-based.
#                if (!instance.NetworkInterfaceId) {
#                    helpers.addResult(results, 2,
#                        'SageMaker Notebook instance not in VPC', region, instanceArn);
#                } else {
#                    helpers.addResult(results, 0,
#                        'SageMaker Notebook instance in VPC', region, instanceArn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }