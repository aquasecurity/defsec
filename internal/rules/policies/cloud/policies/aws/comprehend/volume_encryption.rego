# METADATA
# title :"Amazon Comprehend Volume Encryption"
# description: "Ensures the Comprehend service is using encryption for all volumes storing data at rest."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Comprehend
#   severity: LOW
#   short_code: volume-encryption 
#   recommended_action: "Enable volume encryption for the Comprehend job"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var regions = helpers.regions(settings);
#
#        async.each(regions.comprehend, function(region, rcb) {
#            async.parallel([
#                function(lcb){
#                    var listEntitiesDetectionJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listEntitiesDetectionJobs', region]);
#                        
#                    if (!listEntitiesDetectionJobs) return lcb();
#
#                    if (listEntitiesDetectionJobs.err || !listEntitiesDetectionJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for entities detections jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listEntitiesDetectionJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No entities detection jobs found', region);
#                        return lcb();
#                    }
#
#                    loopJobsForResults(listEntitiesDetectionJobs, results, region);
#
#                    lcb();
#                },
#                function(lcb){
#                    var listDocumentClassificationJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listDocumentClassificationJobs', region]);
#
#                    if (!listDocumentClassificationJobs) return lcb();
#                    
#                    if (listDocumentClassificationJobs.err || !listDocumentClassificationJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for document classification jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listDocumentClassificationJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No document classification jobs found', region);
#                        return lcb();
#                    }
#                    
#                    loopJobsForResults(listDocumentClassificationJobs, results, region);
#
#                    lcb();
#                },
#                function(lcb){
#                    var listDominantLanguageDetectionJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listDominantLanguageDetectionJobs', region]);
#                    
#                    if (!listDominantLanguageDetectionJobs) return lcb();
#
#                    if (listDominantLanguageDetectionJobs.err || !listDominantLanguageDetectionJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for dominant language detection jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listDominantLanguageDetectionJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No dominant language detection jobs found', region);
#                        return lcb();
#                    }
#
#                    loopJobsForResults(listDominantLanguageDetectionJobs, results, region);
#
#                    lcb();
#                },
#                function(lcb){                    
#                    var listTopicsDetectionJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listTopicsDetectionJobs', region]);
#                    
#                    if (!listTopicsDetectionJobs) return lcb();
#
#                    if (listTopicsDetectionJobs.err || !listTopicsDetectionJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for topics detection jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listTopicsDetectionJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No topics detection jobs found', region);
#                        return lcb();
#                    }
#
#                    loopJobsForResults(listTopicsDetectionJobs, results, region);
#
#                    lcb();
#                },
#                function(lcb){       
#                    var listKeyPhrasesDetectionJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listKeyPhrasesDetectionJobs', region]);
#                    
#                    if (!listKeyPhrasesDetectionJobs) return lcb();
#
#                    if (listKeyPhrasesDetectionJobs.err || !listKeyPhrasesDetectionJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for key phrases detection jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listKeyPhrasesDetectionJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No key phrases detection jobs found', region);
#                        return lcb();
#                    }
#
#                    loopJobsForResults(listKeyPhrasesDetectionJobs, results, region);
#
#                    lcb();
#                },
#                function(lcb){                    
#                    var listSentimentDetectionJobs = helpers.addSource(cache, source,
#                        ['comprehend', 'listSentimentDetectionJobs', region]);
#                    
#                    if (!listSentimentDetectionJobs) return lcb();
#
#                    if (listSentimentDetectionJobs.err || !listSentimentDetectionJobs.data) {
#                        helpers.addResult(results, 3,
#                            'Unable to query for sentiment detection jobs', region);
#                        return lcb();
#                    }
#
#                    if (!listSentimentDetectionJobs.data.length) {
#                        helpers.addResult(results, 0,
#                            'No sentiment detection jobs found', region);
#                        return lcb();
#                    }
#
#                    loopJobsForResults(listSentimentDetectionJobs, results, region);
#
#                    lcb();
#                },
#            ], function(){
#                rcb();
#            });
#        }, function() {
#            callback(null, results, source);
#        });
#    }