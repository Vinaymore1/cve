const fs = require('fs');
const path = require('path');
const { createCVEModel } = require('../models/CVE');

const cveListPath = path.join(__dirname, '../../cvelistV5/cves');

async function parseCVEData(db, changedFiles) {
    const cveCollection = createCVEModel(db);

    // Check if the database has any entries in the `cves` collection
    const totalCVECount = await cveCollection.countDocuments();

    // Perform a full sync if no records exist or count is less than 1000
    if (totalCVECount === 0 || totalCVECount < 1000) {
        console.log(`No CVEs or less than 1000 CVEs found in the database (${totalCVECount}). Performing a full sync for 2024...`);
        await syncFullCVEDataFor2024(cveCollection);
    } else if (changedFiles.length > 0) {
        // If there are modified files, sync only those
        console.log("Modified files found. Syncing modified CVEs...");
        await syncModifiedCVEData(changedFiles, cveCollection);
    } else {
        console.log("No changes detected in git diff. No update required.");
    }
}

async function syncFullCVEDataFor2024(cveCollection) {
    const yearDir = path.join(cveListPath, '2024');

    if (fs.existsSync(yearDir)) {
        let numDirs = fs.readdirSync(yearDir).reverse(); // Reverse to process latest first

        for (const numDir of numDirs) {
            const numDirPath = path.join(yearDir, numDir);
            let cveFiles = fs.readdirSync(numDirPath).filter(file => file.endsWith('.json')).reverse(); // Process files in reverse

            for (const file of cveFiles) {
                await insertCVEFromFile(file, numDirPath, cveCollection);
            }
        }
    } else {
        console.log('Directory for the year 2024 not found');
    }
}

async function syncModifiedCVEData(changedFiles, cveCollection) {
    for (const filePath of changedFiles) {
        if (!filePath.endsWith('.json') || !filePath.startsWith('cves/2024')) {
            continue; // Skip files that do not match the CVE structure
        }

        const pathParts = filePath.split('/');
        if (pathParts.length < 3) {
            console.error("File path is not as expected:", filePath);
            continue;
        }

        const [yearDir, numDir, file] = pathParts.slice(-3);
        const fullFilePath = path.join(cveListPath, yearDir, numDir, file);

        await insertCVEFromFile(file, path.join(cveListPath, yearDir, numDir), cveCollection);
    }
}

async function insertCVEFromFile(file, dirPath, cveCollection) {
    const filePath = path.join(dirPath, file);

    const cveData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const cveId = cveData?.cveMetadata?.cveId;
    const publishedDate = cveData?.cveMetadata?.datePublished;
    const lastModifiedDate = cveData?.cveMetadata?.dateUpdated;

    const description = (cveData?.containers?.cna?.descriptions?.[0]?.value) || 'No description available';

    const cpeData = (cveData?.containers?.cna?.affected || []).map(aff => ({
        vendor: aff.vendor || 'Unknown Vendor',
        product: aff.product || 'Unknown Product',
        versions: aff.versions || []
    }));

    let cvssData = null;
    const metrics = cveData?.containers?.cna?.metrics;
    if (metrics && metrics.length > 0) {
        const cvssV3_1 = metrics.find(metric => metric.cvssV3_1);
        if (cvssV3_1) {
            cvssData = cvssV3_1.cvssV3_1;
        }
    }

    const cweData = (cveData?.containers?.cna?.problemTypes || []).map(pt => ({
        cwe_id: pt.descriptions[0]?.cweId || 'Unknown CWE',
        description: pt.descriptions[0]?.description || 'No CWE description'
    }));

    const capecData = (cveData?.containers?.cna?.impacts || []).map(impact => ({
        capec_id: impact.capecId || 'Unknown CAPEC',
        description: impact.descriptions[0]?.value || 'No CAPEC description'
    }));

    const references = (cveData?.containers?.cna?.references || []).map(ref => ref.url);

    const solution = (cveData?.containers?.cna?.solutions || []).map(solution => ({
        description: solution.value || 'No solution provided',
        media: solution.supportingMedia || []
    }));

    const source = cveData?.containers?.cna?.providerMetadata?.shortName || "MITRE";

    await cveCollection.updateOne(
        { cve_id: cveId },
        {
            $set: {
                cve_id: cveId,
                description,
                published_date: publishedDate ? new Date(publishedDate) : null,
                last_modified: lastModifiedDate ? new Date(lastModifiedDate) : null,
                cpe_data: cpeData,
                cvss_data: cvssData,
                cwe_data: cweData,
                capec_data: capecData,
                references: references,
                solution: solution,
                source: source,
                tag: 'R'
            }
        },
        { upsert: true }  // Insert if it doesn't exist, update if it does
    );
}

module.exports = {
    parseCVEData
};




// const fs = require('fs');
// const path = require('path');
// const { createCVEModel } = require('../models/CVE');

// const cveListPath = path.join(__dirname, '../cvelistV5/cves');

// async function parseCVEData(db, changedFiles) {
//     const cveCollection = createCVEModel(db);
    
//     // Check if the database has any entries for 2024
//     const existingCVEs = await cveCollection.find({}).toArray();
    
//     // If no entries exist for 2024 and no changed files, do a full sync
//     if (existingCVEs.length === 0 && changedFiles.length === 0) {
//         console.log("No CVEs found in the database. Performing a full sync for 2024...");
//         await syncFullCVEDataFor2024(cveCollection);
//     } else if (changedFiles.length > 0) {
//         // If there are modified files, sync only those
//         console.log("Modified files found. Syncing modified CVEs...");
//         await syncModifiedCVEData(changedFiles, cveCollection);
//     } else {
//         console.log("No changes detected in git diff. No update required.");
//     }
// }

// async function syncFullCVEDataFor2024(cveCollection) {
//     const yearDir = path.join(cveListPath, '2024');

//     if (fs.existsSync(yearDir)) {
//         let numDirs = fs.readdirSync(yearDir).reverse(); // Reverse to process latest first

//         for (const numDir of numDirs) {
//             const numDirPath = path.join(yearDir, numDir);
//             let cveFiles = fs.readdirSync(numDirPath).filter(file => file.endsWith('.json')).reverse(); // Process files in reverse

//             for (const file of cveFiles) {
//                 await insertCVEFromFile(file, numDirPath, cveCollection);
//             }
//         }
//     } else {
//         console.log('Directory for the year 2024 not found');
//     }
// }
// async function syncModifiedCVEData(changedFiles, cveCollection) {
//     for (const filePath of changedFiles) {
//         // console.log("Processing file:", filePath); // Log the file being processed

//         // Check if the file is a CVE JSON file (you can adjust the regex as needed)
//         if (!filePath.endsWith('.json') || !filePath.startsWith('cves/2024')) {
//             // console.log(`Skipping non-CVE file: ${filePath}`);
//             continue; // Skip files that do not match the CVE structure
//         }

//         const pathParts = filePath.split('/'); // Split the path
//         // Ensure there are enough parts to extract yearDir, numDir, and file
//         if (pathParts.length < 3) {
//             console.error("File path is not as expected:", filePath);
//             continue; // Skip this iteration if the path is not valid
//         }

//         const [yearDir, numDir, file] = pathParts.slice(-3); // Extract the last three parts
//         const fullFilePath = path.join(cveListPath, yearDir, numDir, file);
//         // console.log("Full file path:", fullFilePath); // Log the full path

//         await insertCVEFromFile(file, path.join(cveListPath, yearDir, numDir), cveCollection);
//     }
// }


// // async function syncModifiedCVEData(changedFiles, cveCollection) {
// //     for (const filePath of changedFiles) {
// //         console.log("Processing file:", filePath); // Add this line to log the file being processed
// //         const pathParts = filePath.split('/'); // Split the path

// //         // Ensure there are enough parts to extract yearDir, numDir, and file
// //         if (pathParts.length < 3) {
// //             console.error("File path is not as expected:", filePath);
// //             continue; // Skip this iteration if the path is not valid
// //         }

// //         const [yearDir, numDir, file] = pathParts.slice(-3); // Extract the last three parts

// //         const fullFilePath = path.join(cveListPath, yearDir, numDir, file);
// //         console.log("Full file path:", fullFilePath); // Add this line to verify the full path

// //         await insertCVEFromFile(file, path.join(cveListPath, yearDir, numDir), cveCollection);
// //     }
// // }


// async function insertCVEFromFile(file, dirPath, cveCollection) {
//     const filePath = path.join(dirPath, file);
    
//     // Read the JSON file
//     const cveData = JSON.parse(fs.readFileSync(filePath, 'utf8'));

//     const cveId = cveData?.cveMetadata?.cveId;
//     const publishedDate = cveData?.cveMetadata?.datePublished;
//     const lastModifiedDate = cveData?.cveMetadata?.dateUpdated;

//     // Safely extract description
//     const description = (cveData?.containers?.cna?.descriptions?.[0]?.value) || 'No description available';

//     // Extract CPE Data
//     const cpeData = (cveData?.containers?.cna?.affected || []).map(aff => ({
//         vendor: aff.vendor || 'Unknown Vendor',
//         product: aff.product || 'Unknown Product',
//         versions: aff.versions || []
//     }));

//     // Safely extract CVSS data
//     let cvssData = null;
//     const metrics = cveData?.containers?.cna?.metrics;
//     if (metrics && metrics.length > 0) {
//         const cvssV3_1 = metrics.find(metric => metric.cvssV3_1);
//         if (cvssV3_1) {
//             cvssData = cvssV3_1.cvssV3_1;
//         }
//     }

//     // Extract CWE data
//     const cweData = (cveData?.containers?.cna?.problemTypes || []).map(pt => ({
//         cwe_id: pt.descriptions[0]?.cweId || 'Unknown CWE',
//         description: pt.descriptions[0]?.description || 'No CWE description'
//     }));

//     // Extract CAPEC data
//     const capecData = (cveData?.containers?.cna?.impacts || []).map(impact => ({
//         capec_id: impact.capecId || 'Unknown CAPEC',
//         description: impact.descriptions[0]?.value || 'No CAPEC description'
//     }));

//     // Extract references
//     const references = (cveData?.containers?.cna?.references || []).map(ref => ref.url);

//     // Extract solution data (if present)
//     const solution = (cveData?.containers?.cna?.solutions || []).map(solution => ({
//         description: solution.value || 'No solution provided',
//         media: solution.supportingMedia || []
//     }));

//     // Extract discovery source
//     const source = cveData?.containers?.cna?.providerMetadata?.shortName || "MITRE";

//     // Insert CVE into MongoDB with all additional fields
//     await cveCollection.updateOne(
//         { cve_id: cveId },
//         {
//             $set: {
//                 cve_id: cveId,
//                 description,
//                 published_date: publishedDate ? new Date(publishedDate) : null,
//                 last_modified: lastModifiedDate ? new Date(lastModifiedDate) : null,
//                 cpe_data: cpeData,
//                 cvss_data: cvssData,
//                 cwe_data: cweData,
//                 capec_data: capecData,
//                 references: references,
//                 solution: solution,
//                 source: source
//             }
//         },
//         { upsert: true }  // Insert if it doesn't exist, update if it does
//     );
// }


// module.exports = {
//     parseCVEData
// };





