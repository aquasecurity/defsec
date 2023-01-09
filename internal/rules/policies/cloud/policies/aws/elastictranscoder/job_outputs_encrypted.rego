# METADATA
# title :"Elastic Transcoder Job Outputs Encrypted"
# description: "Ensure that Elastic Transcoder jobs have encryption enabled to encrypt your data before saving on S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Elastic Transcoder
#   severity: LOW
#   short_code: job-outputs-encrypted 
#   recommended_action: "Enable encryption for Elastic Transcoder job outputs"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elastictranscoder, function(region, rcb){
#            var listPipelines = helpers.addSource(cache, source,
#                ['elastictranscoder', 'listPipelines', region]);
#
#            if (!listPipelines) return rcb();
#
#            if (listPipelines.err || !listPipelines.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list Elastic Transcoder pipelines: ${helpers.addError(listPipelines)}`, region);
#                return rcb();
#            }
#
#            if (!listPipelines.data.length) {
#                helpers.addResult(results, 0,
#                    'No Elastic Transcoder pipelines found', region);
#                return rcb();
#            }
#
#            for (let pipeline of listPipelines.data) {
#                if (!pipeline.Id) continue;
#
#                let pipelineJobs = helpers.addSource(cache, source,
#                    ['elastictranscoder', 'listJobsByPipeline', region, pipeline.Id]);
#
#                if (!pipelineJobs || pipelineJobs.err || !pipelineJobs.data || !pipelineJobs.data.Jobs) {
#                    helpers.addResult(results, 3,
#                        `Unable to list Elastic Transcoder jobs for pipeline: ${helpers.addError(pipelineJobs)}`, region, pipeline.Arn);
#                    continue;
#                }
#    
#                if (!pipelineJobs.data.Jobs.length) {
#                    helpers.addResult(results, 0,
#                        'No Elastic Transcoder jobs found for pipeline', region, pipeline.Arn);
#                    continue;
#                }
#
#                for (let job of pipelineJobs.data.Jobs) {
#                    if (job.Status && job.Status.toUpperCase() == 'ERROR') {
#                        helpers.addResult(results, 0,
#                            'Job status is "Error"', region, job.Arn);
#                    } else {
#                        if (job.Outputs && job.Outputs.length) var unencryptedOutputs = job.Outputs.find(output => !output.Encryption);
#                        else helpers.addResult(results, 0, 'Job does not have any outputs', region, job.Arn);
#
#                        if (unencryptedOutputs) {
#                            helpers.addResult(results, 2,
#                                'Job does not encryption enabled for one or more outputs', region, job.Arn);
#                        } else {
#                            helpers.addResult(results, 0,
#                                'Job has encryption enabled for outputs', region, job.Arn);
#                        }
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }