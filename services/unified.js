const { ObjectId } = require('mongodb');

// Models for the three sources and unified collection
const createCVEModel = (db) => db.collection('cves');
const createCVEMapModel = (db) => db.collection('cvemap');
const createnvdModel = (db) => db.collection('nvd');
const createUnifiedModel = (db) => db.collection('unified_cves');

// Unified Merge Function
async function parseUnifiedData(db) {
    const cveCollection = createCVEModel(db);
    const cveMapCollection = createCVEMapModel(db);
    const nvdCollection = createnvdModel(db);
    const unifiedCollection = createUnifiedModel(db);

    // Fetch only CVE IDs with the tag 'R'
    const allCVEIds = await cveCollection.distinct('cve_id', { tag: 'R' });
    console.log(`Found ${allCVEIds.length} CVE IDs with tag 'R'`); // Log the number of CVE IDs found

    if (allCVEIds.length === 0) {
        console.log('No CVE IDs found with tag "R".');
        return;
    }

    // Prepare bulk operations
    const unifiedBulkOps = [];
    const mitreBulkOps = [];
    const nvdBulkOps = [];
    const cvemapBulkOps = [];

    // Iterate through all CVE IDs with tag 'R'
    for (const cveId of allCVEIds) {
        // Fetch data from each source (MITRE, NVD, CVEMap)
        const mitreData = await cveCollection.findOne({ cve_id: cveId, tag: 'R' });
        const nvdData = await nvdCollection.findOne({ cve_id: cveId, tag: 'R' });
        const cvemapData = await cveMapCollection.findOne({ cve_id: cveId, tag: 'R' });

        // Merging logic with preference: MITRE > NVD > CVEMap
        const unifiedData = {
            cve_id: cveId,
            description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
            severity: mitreData?.cvss_data?.baseSeverity || nvdData?.severity || cvemapData?.severity || null,
            cvss_score: mitreData?.cvss_data?.baseScore || nvdData?.cvss_score || cvemapData?.cvss_score || null,
            cvss_metrics: mitreData?.cvss_data || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
            weaknesses: mitreData?.cwe_data || nvdData?.weaknesses || cvemapData?.weaknesses || [],
            epss: cvemapData?.epss || null,  // Assuming CVEMap has this data
            cpe: mitreData?.cpe_data || null, // Adjusted for CPE data source
            references: mitreData?.references || nvdData?.references || cvemapData?.vendor_advisory || [],
            vendor_advisory: cvemapData?.vendor_advisory || nvdData?.references || null,
            is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
            is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
            assignee: cvemapData?.assignee || null,
            published_at: mitreData?.published_date || nvdData?.published_at || cvemapData?.published_at || null,
            updated_at: mitreData?.last_modified || nvdData?.updated_at || cvemapData?.updated_at || null,
            hackerone: null,  // If applicable
            age_in_days: cvemapData?.age_in_days || null,
            vuln_status: cvemapData?.vuln_status || null,
            is_poc: cvemapData?.is_poc || false,
            is_remote: cvemapData?.is_remote || false,
            is_oss: cvemapData?.is_oss || false,
            vulnerable_cpe: mitreData?.cpe_data || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
            source: 'Unified',  // Merged data comes from multiple sources
            tag: 'N'  // Mark as 'N' in the unified collection after merging
        };

        // Add to unified bulk operations
        unifiedBulkOps.push({
            updateOne: {
                filter: { cve_id: cveId },
                update: { $set: unifiedData },
                upsert: true
            }
        });

        // Update original collections with 'N' after processing
        if (mitreData) {
            mitreBulkOps.push({
                updateOne: {
                    filter: { cve_id: cveId },
                    update: { $set: { tag: 'N' } }
                }
            });
        }

        if (nvdData) {
            nvdBulkOps.push({
                updateOne: {
                    filter: { cve_id: cveId },
                    update: { $set: { tag: 'N' } }
                }
            });
        }

        if (cvemapData) {
            cvemapBulkOps.push({
                updateOne: {
                    filter: { cve_id: cveId },
                    update: { $set: { tag: 'N' } }
                }
            });
        }
    }

    // Execute bulk write operations
    if (unifiedBulkOps.length > 0) {
        await unifiedCollection.bulkWrite(unifiedBulkOps);
    }

    if (mitreBulkOps.length > 0) {
        await cveCollection.bulkWrite(mitreBulkOps);
    }

    if (nvdBulkOps.length > 0) {
        await nvdCollection.bulkWrite(nvdBulkOps);
    }

    if (cvemapBulkOps.length > 0) {
        await cveMapCollection.bulkWrite(cvemapBulkOps);
    }

    console.log('Unified data processing completed.');
}

module.exports = { parseUnifiedData };

// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     const allCVEIds = await cveCollection.distinct('cve_id');
//     console.log(`Found ${allCVEIds.length} CVE IDs`); // Log the number of CVE IDs found

//     if (allCVEIds.length === 0) {
//         console.log('No CVE IDs found in MITRE data.');
//         return;
//     }

//     // Prepare bulk operations
//     const unifiedBulkOps = [];
//     const mitreBulkOps = [];
//     const nvdBulkOps = [];
//     const cvemapBulkOps = [];

//     // Remove the slicing to process all CVE IDs
//     for (const cveId of allCVEIds) {
//         // Fetch data from each source (MITRE, NVD, CVEMap)
//         const mitreData = await cveCollection.findOne({ cve_id: cveId });
//         const nvdData = await nvdCollection.findOne({ cve_id: cveId });
//         const cvemapData = await cveMapCollection.findOne({ cve_id: cveId });

//         // Merging logic with preference: MITRE > NVD > CVEMap
//         const unifiedData = {
//             cve_id: cveId,
//             description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
//             severity: mitreData?.cvss_data?.baseSeverity || nvdData?.severity || cvemapData?.severity || null,
//             cvss_score: mitreData?.cvss_data?.baseScore || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//             cvss_metrics: mitreData?.cvss_data || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//             weaknesses: mitreData?.cwe_data || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//             epss: cvemapData?.epss || null,  // Assuming CVEMap has this data
//             cpe: mitreData?.cpe_data || null, // Adjusted for CPE data source
//             references: mitreData?.references || nvdData?.references || cvemapData?.vendor_advisory || [],
//             vendor_advisory: cvemapData?.vendor_advisory || nvdData?.references || null,
//             is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//             is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//             assignee: cvemapData?.assignee || null,
//             published_at: mitreData?.published_date || nvdData?.published_at || cvemapData?.published_at || null,
//             updated_at: mitreData?.last_modified || nvdData?.updated_at || cvemapData?.updated_at || null,
//             hackerone: null,  // If applicable
//             age_in_days: cvemapData?.age_in_days || null,
//             vuln_status: cvemapData?.vuln_status || null,
//             is_poc: cvemapData?.is_poc || false,
//             is_remote: cvemapData?.is_remote || false,
//             is_oss: cvemapData?.is_oss || false,
//             vulnerable_cpe: mitreData?.cpe_data || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//             source: 'Unified',  // Merged data comes from multiple sources
//             tag: 'N'  // Mark as 'N' in the unified collection after merging
//         };

//         // Add to unified bulk operations
//         unifiedBulkOps.push({
//             updateOne: {
//                 filter: { cve_id: cveId },
//                 update: { $set: unifiedData },
//                 upsert: true
//             }
//         });

//         // Update original collections with 'N' after processing
//         if (mitreData) {
//             mitreBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (nvdData) {
//             nvdBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (cvemapData) {
//             cvemapBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }
//     }

//     // Execute bulk write operations
//     if (unifiedBulkOps.length > 0) {
//         await unifiedCollection.bulkWrite(unifiedBulkOps);
//     }

//     if (mitreBulkOps.length > 0) {
//         await cveCollection.bulkWrite(mitreBulkOps);
//     }

//     if (nvdBulkOps.length > 0) {
//         await nvdCollection.bulkWrite(nvdBulkOps);
//     }

//     if (cvemapBulkOps.length > 0) {
//         await cveMapCollection.bulkWrite(cvemapBulkOps);
//     }

//     console.log('Unified data processing completed.');
// }

// module.exports = { parseUnifiedData };




// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     const allCVEIds = await cveCollection.distinct('cve_id');
//     // console.log(`Found ${allCVEIds.length} CVE IDs`);

//     if (allCVEIds.length === 0) {
//         console.log('No CVE IDs found in MITRE data.');
//         return;
//     }

//     // Prepare bulk operations
//     const unifiedBulkOps = [];
//     const mitreBulkOps = [];
//     const nvdBulkOps = [];
//     const cvemapBulkOps = [];
//     const sampleCVEIds = allCVEIds.slice(0, 10);
//     for (const cveId of sampleCVEIds) {
//         // Fetch data from each source (MITRE, NVD, CVEMap)
//         const mitreData = await cveCollection.findOne({ cve_id: cveId });
//         const nvdData = await nvdCollection.findOne({ cve_id: cveId });
//         const cvemapData = await cveMapCollection.findOne({ cve_id: cveId });
//         // console.log(`MITRE Data for ${cveId}: ${!!mitreData}`);
//         // console.log(`NVD Data for ${cveId}: ${!!nvdData}`);
//         // console.log(`CVEMap Data for ${cveId}: ${!!cvemapData}`);

//         // Merging logic with preference: MITRE > NVD > CVEMap
//         const unifiedData = {
//             cve_id: cveId,
//             description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
//             severity: mitreData?.severity || nvdData?.severity || cvemapData?.severity || null,
//             cvss_score: mitreData?.cvss_score || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//             cvss_metrics: mitreData?.cvss_metrics || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//             weaknesses: mitreData?.weaknesses || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//             epss: mitreData?.epss || nvdData?.epss || cvemapData?.epss || null,
//             cpe: mitreData?.cpe || nvdData?.cpe || cvemapData?.cpe || null,
//             references: mitreData?.references || nvdData?.references || cvemapData?.references || [],
//             vendor_advisory: mitreData?.vendor_advisory || nvdData?.vendor_advisory || cvemapData?.vendor_advisory || null,
//             is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//             is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//             assignee: mitreData?.assignee || nvdData?.assignee || cvemapData?.assignee || null,
//             published_at: mitreData?.published_at || nvdData?.published_at || cvemapData?.published_at || null,
//             updated_at: mitreData?.updated_at || nvdData?.updated_at || cvemapData?.updated_at || null,
//             hackerone: mitreData?.hackerone || nvdData?.hackerone || cvemapData?.hackerone || null,
//             age_in_days: mitreData?.age_in_days || nvdData?.age_in_days || cvemapData?.age_in_days || null,
//             vuln_status: mitreData?.vuln_status || nvdData?.vuln_status || cvemapData?.vuln_status || null,
//             is_poc: mitreData?.is_poc || nvdData?.is_poc || cvemapData?.is_poc || false,
//             is_remote: mitreData?.is_remote || nvdData?.is_remote || cvemapData?.is_remote || false,
//             is_oss: mitreData?.is_oss || nvdData?.is_oss || cvemapData?.is_oss || false,
//             vulnerable_cpe: mitreData?.vulnerable_cpe || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//             source: 'Unified',  // Merged data comes from multiple sources
//             tag: 'N'  // Mark as 'N' in the unified collection after merging
//         };

//         // Add to unified bulk operations
//         unifiedBulkOps.push({
//             updateOne: {
//                 filter: { cve_id: cveId },
//                 update: { $set: unifiedData },
//                 upsert: true
//             }
//         });

//         // Update original collections with 'N' after processing
//         if (mitreData) {
//             mitreBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (nvdData) {
//             nvdBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (cvemapData) {
//             cvemapBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }
//     }

//     // Execute bulk write operations
//     if (unifiedBulkOps.length > 0) {
//         await unifiedCollection.bulkWrite(unifiedBulkOps);
//     }

//     if (mitreBulkOps.length > 0) {
//         await cveCollection.bulkWrite(mitreBulkOps);
//     }

//     if (nvdBulkOps.length > 0) {
//         await nvdCollection.bulkWrite(nvdBulkOps);
//     }

//     if (cvemapBulkOps.length > 0) {
//         await cveMapCollection.bulkWrite(cvemapBulkOps);
//     }

//     console.log('Unified CVE data merged successfully.');
// }

// module.exports = {
//     parseUnifiedData
// };


// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function with Batch Processing
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     // Fetch CVE data from MITRE, sorting by published_at descending
//     const mitreData = await cveCollection.find({ tag: 'R' }).sort({ published_at: -1 }).toArray();
//     console.log(`Found ${mitreData.length} CVE entries from MITRE with tag 'R'`);

//     if (mitreData.length === 0) {
//         console.log('No CVE entries found in MITRE with tag "R".');
//         return;
//     }

//     // Define batch size
//     const batchSize = 1000;

//     for (let i = 0; i < mitreData.length; i += batchSize) {
//         const batchMitreData = mitreData.slice(i, i + batchSize);
//         console.log(`Processing batch from ${i + 1} to ${i + batchSize}`);

//         // Prepare bulk operations
//         const unifiedBulkOps = [];
//         const nvdBulkOps = [];
//         const cvemapBulkOps = [];

//         for (const mitreEntry of batchMitreData) {
//             const cveId = mitreEntry.cve_id;

//             // Fetch data from NVD and CVEMap
//             const nvdData = await nvdCollection.findOne({ cve_id: cveId, tag: 'R' });
//             const cvemapData = await cveMapCollection.findOne({ cve_id: cveId, tag: 'R' });

//             // Merging logic: prefer MITRE, then NVD, then CVEMap
//             const unifiedData = {
//                 cve_id: cveId,
//                 description: mitreEntry.description || nvdData?.description || cvemapData?.description || 'No description available',
//                 severity: mitreEntry.severity || nvdData?.severity || cvemapData?.severity || null,
//                 cvss_score: mitreEntry.cvss_score || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//                 cvss_metrics: mitreEntry.cvss_metrics || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//                 weaknesses: mitreEntry.weaknesses || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//                 epss: mitreEntry.epss || nvdData?.epss || cvemapData?.epss || null,
//                 cpe: mitreEntry.cpe || nvdData?.cpe || cvemapData?.cpe || null,
//                 references: mitreEntry.references || nvdData?.references || cvemapData?.references || [],
//                 vendor_advisory: mitreEntry.vendor_advisory || nvdData?.vendor_advisory || cvemapData?.vendor_advisory || null,
//                 is_template: mitreEntry.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//                 is_exploited: mitreEntry.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//                 assignee: mitreEntry.assignee || nvdData?.assignee || cvemapData?.assignee || null,
//                 published_at: mitreEntry.published_at || nvdData?.published_at || cvemapData?.published_at || null,
//                 updated_at: mitreEntry.updated_at || nvdData?.updated_at || cvemapData?.updated_at || null,
//                 hackerone: mitreEntry.hackerone || nvdData?.hackerone || cvemapData?.hackerone || null,
//                 age_in_days: mitreEntry.age_in_days || nvdData?.age_in_days || cvemapData?.age_in_days || null,
//                 vuln_status: mitreEntry.vuln_status || nvdData?.vuln_status || cvemapData?.vuln_status || null,
//                 is_poc: mitreEntry.is_poc || nvdData?.is_poc || cvemapData?.is_poc || false,
//                 is_remote: mitreEntry.is_remote || nvdData?.is_remote || cvemapData?.is_remote || false,
//                 is_oss: mitreEntry.is_oss || nvdData?.is_oss || cvemapData?.is_oss || false,
//                 vulnerable_cpe: mitreEntry.vulnerable_cpe || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//                 source: 'Unified',  // Merged data comes from multiple sources
//                 tag: 'N'  // Mark as 'N' in the unified collection after merging
//             };

//             // Add to unified bulk operations
//             unifiedBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: unifiedData },
//                     upsert: true
//                 }
//             });

//             // Update original collections with 'N' after processing
//             if (nvdData) {
//                 nvdBulkOps.push({
//                     updateOne: {
//                         filter: { cve_id: cveId },
//                         update: { $set: { tag: 'N' } }
//                     }
//                 });
//             }

//             if (cvemapData) {
//                 cvemapBulkOps.push({
//                     updateOne: {
//                         filter: { cve_id: cveId },
//                         update: { $set: { tag: 'N' } }
//                     }
//                 });
//             }
//         }

//         // Execute bulk write operations for this batch
//         if (unifiedBulkOps.length > 0) {
//             await unifiedCollection.bulkWrite(unifiedBulkOps);
//             unifiedBulkOps.length = 0; // Clear the bulk operations
//         }

//         if (nvdBulkOps.length > 0) {
//             await nvdCollection.bulkWrite(nvdBulkOps);
//             nvdBulkOps.length = 0;
//         }

//         if (cvemapBulkOps.length > 0) {
//             await cveMapCollection.bulkWrite(cvemapBulkOps);
//             cvemapBulkOps.length = 0;
//         }

//         console.log(`Batch from ${i + 1} to ${i + batchSize} processed successfully.`);
//     }

//     console.log('All CVE data processed and merged.');
// }

// module.exports = {
//     parseUnifiedData
// };




            