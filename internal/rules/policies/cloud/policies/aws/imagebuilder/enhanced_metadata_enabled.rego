# METADATA
# title :"Enhanced Metadata Collection Enabled"
# description: "Ensure that enhanced metadata collection is enabled for image pipelines."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/imagebuilder/latest/userguide/start-build-image-pipeline.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Image Builder
#   severity: LOW
#   short_code: enhanced-metadata-enabled 
#   recommended_action: "Enable enhanced metadata collection for image pipeline."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        async.each(regions.imagebuilder, function(region, rcb){
#            var listImagePipelines = helpers.addSource(cache, source,
#                ['imagebuilder', 'listImagePipelines', region]);
#            
#            if (!listImagePipelines) return rcb();
#
#            if (listImagePipelines.err || !listImagePipelines.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list image pipeline: ' + helpers.addError(listImagePipelines), region);
#                return rcb();
#            }
#
#            if (!listImagePipelines.data.length) {
#                helpers.addResult(results, 0,
#                    'No Image Builder image pipelines found', region);
#                return rcb();
#            }
#
#            for (let image of listImagePipelines.data) {
#                if (!image.arn) continue;
#
#                let resource = image.arn;
#
#                if (image.enhancedImageMetadataEnabled) {
#                    helpers.addResult(results, 0,
#                        'Image pipeline has enhanced metadata collection enabled',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Image pipeline does not have enhanced metadata collection enabled',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }