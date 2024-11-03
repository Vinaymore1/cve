const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const zlib = require('zlib');  // Make sure to import zlib

const { createnvdModel } = require('../models/CVE');

const nvdPath = path.join(__dirname, '../../nvd'); // Path to NVD data files

async function parseNVDData(db) {
    const nvdCollection = createnvdModel(db);

    // Check if the collection already has data
    const count = await nvdCollection.countDocuments();
    
    if (count === 0) {
        console.log('NVD collection is empty. Initial parsing will occur.');
        await initialNVDParsing(nvdCollection);
    } else {
        console.log('NVD collection already has data. Handling modified NVD data.');
        await handleModifiedNVDData(nvdCollection);
    }
}

async function initialNVDParsing(nvdCollection) {
    // Your logic for initial parsing of NVD data (not modified)
    const filePath = path.join(nvdPath, 'nvdcve-1.1-2024.json'); // Change to the correct file name
    const data = await fs.readFile(filePath, 'utf8');
    const parsedData = JSON.parse(data);
    const jsonArray = parsedData.CVE_Items;

    if (!Array.isArray(jsonArray)) {
        throw new Error("Expected an array of CVE Items");
    }

    // Sort the array by published_at date in descending order (latest to oldest)
    jsonArray.sort((a, b) => new Date(b.publishedDate) - new Date(a.publishedDate));

    for (const item of jsonArray) {
        await insertNVDEntry(item, nvdCollection);
    }

    console.log('Initial NVD data for 2024 successfully inserted from latest to oldest.');
}

async function handleModifiedNVDData(nvdCollection) {
    const modifiedFilePath = path.join(nvdPath, 'nvdcve-1.1-modified.json'); // Path to modified NVD data file

    // Delete any existing modified data file if it exists
    try {
        await fs.unlink(modifiedFilePath);
        console.log('Deleted existing modified NVD data file.');
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error('Error deleting existing modified NVD data file:', error);
        } else {
            console.log('No existing modified NVD data file found to delete.');
        }
    }

    const url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz';

    try {
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        const gzFilePath = path.join(nvdPath, 'nvdcve-1.1-modified.json.gz');

        // Save the downloaded file
        await fs.writeFile(gzFilePath, response.data);
        console.log('Downloaded modified NVD data.');

        // Unzip the downloaded file
        await unzipFile(gzFilePath, modifiedFilePath);

        // Proceed with parsing the unzipped modified data
        const data = await fs.readFile(modifiedFilePath, 'utf8');
        const parsedData = JSON.parse(data);

        await processNVDJson(parsedData, nvdCollection);

        console.log('Modified NVD data successfully inserted.');
    } catch (error) {
        console.error('Error handling modified NVD data:', error);
    }
}

async function unzipFile(gzFilePath, outputFilePath) {
    const fileContent = await fs.readFile(gzFilePath);
    
    const unzippedContent = await new Promise((resolve, reject) => {
        zlib.gunzip(fileContent, (err, buffer) => {
            if (err) {
                reject(err);
            } else {
                resolve(buffer);
            }
        });
    });

    // Save the unzipped file
    await fs.writeFile(outputFilePath, unzippedContent);
    console.log(`Unzipped modified data saved to ${outputFilePath}`);
}

async function processNVDJson(parsedData, nvdCollection) {
    const jsonArray = parsedData.CVE_Items;

    if (!Array.isArray(jsonArray)) {
        throw new Error("Expected an array of CVE Items");
    }

    // Sort the array by published_at date in descending order (latest to oldest)
    jsonArray.sort((a, b) => new Date(b.publishedDate) - new Date(a.publishedDate));

    for (const item of jsonArray) {
        await insertNVDEntry(item, nvdCollection);
    }

    console.log('NVD data successfully inserted from latest to oldest.');
}
async function insertNVDEntry(item, nvdCollection) {
    const cveId = item.cve.CVE_data_meta.ID;
    const description = item.cve.description.description_data[0]?.value || 'No description provided';
    const source = 'NVD';

    // CVSS v3 base score and metrics (V3 is more recent than V2)
    const cvssScore = item.impact?.baseMetricV3?.cvssV3?.baseScore || null;
    const cvssMetrics = item.impact?.baseMetricV3?.cvssV3 || null;

    // CVSS v2 metrics if V3 is not available
    const cvssScoreV2 = item.impact?.baseMetricV2?.cvssV2?.baseScore || null;
    const cvssMetricsV2 = item.impact?.baseMetricV2?.cvssV2 || null;

    // Weaknesses (CWE information)
    const weaknesses = item.cve.problemtype.problemtype_data[0]?.description.map(w => ({
        cwe_id: w.value,
        cwe_name: w.value // The description is sometimes identical to the value
    })) || [];

    // References (URLs for more details)
    const references = item.cve.references.reference_data.map(ref => ref.url) || [];

    // CPE data (Common Platform Enumeration) - List of affected software, hardware, etc.
    const vulnerableCPE = item.configurations?.nodes?.map(node => node.cpe_match?.map(cpe => cpe.cpe23Uri)).flat() || [];

    // Other impact information
    const isExploited = !!item.impact?.baseMetricV3?.exploitabilityScore;
    const severity = item.impact?.baseMetricV3?.cvssV3?.baseSeverity || 'Unknown';

    // Published and updated dates
    const publishedAt = new Date(item.publishedDate);
    const updatedAt = new Date(item.lastModifiedDate);

    // Insert the NVD entry
    await nvdCollection.updateOne(
        { cve_id: cveId },
        {
            $set: {
                cve_id: cveId,
                description,
                cvss_score: cvssScore,
                cvss_metrics: cvssMetrics,
                cvss_score_v2: cvssScoreV2,
                cvss_metrics_v2: cvssMetricsV2,
                weaknesses,
                references,
                vulnerable_cpe: vulnerableCPE,
                is_exploited: isExploited,
                severity,
                published_at: publishedAt,
                updated_at: updatedAt,
                source,
                tag: 'R' // Mark newly added or modified items as 'R' (Required for unified collection)
            }
        },
        { upsert: true } // Insert if it doesn't exist, update if it does
    );
}

module.exports = {
    parseNVDData
};

// const fs = require('fs').promises;
// const path = require('path');
// const { createnvdModel } = require('../models/CVE');

// const nvdPath = path.join(__dirname, '../nvd'); // Path to NVD data files

// async function parseNVDData(db) {
//     const nvdCollection = createnvdModel(db);

//     // Update to correctly parse NVD data
//     const filePath = path.join(nvdPath, 'nvdcve-1.1-2024.json'); // Change to the correct file name
//     const data = await fs.readFile(filePath, 'utf8');
//     const parsedData = JSON.parse(data);

//     // NVD data is nested under 'CVE_Items'
//     const jsonArray = parsedData.CVE_Items;

//     if (!Array.isArray(jsonArray)) {
//         throw new Error("Expected an array of CVE Items");
//     }

//     // Sort the array by published_at date in descending order (latest to oldest)
//     jsonArray.sort((a, b) => new Date(b.publishedDate) - new Date(a.publishedDate));

//     for (const item of jsonArray) {
//         await insertNVDEntry(item, nvdCollection);
//     }

//     console.log('NVD data for 2024 successfully inserted from latest to oldest.');
// }

// async function insertNVDEntry(item, nvdCollection) {
//     const cveId = item.cve.CVE_data_meta.ID;
//     const description = item.cve.description.description_data[0]?.value || 'No description provided';
//     const source = 'NVD';

//     // CVSS v3 base score and metrics (V3 is more recent than V2)
//     const cvssScore = item.impact?.baseMetricV3?.cvssV3?.baseScore || null;
//     const cvssMetrics = item.impact?.baseMetricV3?.cvssV3 || null;

//     // CVSS v2 metrics if V3 is not available
//     const cvssScoreV2 = item.impact?.baseMetricV2?.cvssV2?.baseScore || null;
//     const cvssMetricsV2 = item.impact?.baseMetricV2?.cvssV2 || null;

//     // Weaknesses (CWE information)
//     const weaknesses = item.cve.problemtype.problemtype_data[0]?.description.map(w => ({
//         cwe_id: w.value,
//         cwe_name: w.value // The description is sometimes identical to the value
//     })) || [];

//     // References (URLs for more details)
//     const references = item.cve.references.reference_data.map(ref => ref.url) || [];

//     // CPE data (Common Platform Enumeration) - List of affected software, hardware, etc.
//     const vulnerableCPE = item.configurations?.nodes?.map(node => node.cpe_match?.map(cpe => cpe.cpe23Uri)).flat() || [];

//     // Other impact information
//     const isExploited = !!item.impact?.baseMetricV3?.exploitabilityScore;
//     const severity = item.impact?.baseMetricV3?.cvssV3?.baseSeverity || 'Unknown';

//     // Published and updated dates
//     const publishedAt = new Date(item.publishedDate);
//     const updatedAt = new Date(item.lastModifiedDate);

//     // Insert the NVD entry
//     await nvdCollection.updateOne(
//         { cve_id: cveId },
//         {
//             $set: {
//                 cve_id: cveId,
//                 description,
//                 cvss_score: cvssScore,
//                 cvss_metrics: cvssMetrics,
//                 cvss_score_v2: cvssScoreV2,
//                 cvss_metrics_v2: cvssMetricsV2,
//                 weaknesses,
//                 references,
//                 vulnerable_cpe: vulnerableCPE,
//                 is_exploited: isExploited,
//                 severity,
//                 published_at: publishedAt,
//                 updated_at: updatedAt,
//                 source,
//                 tag: 'R' // Mark newly added or modified items as 'R' (Required for unified collection)
//             }
//         },
//         { upsert: true } // Insert if it doesn't exist, update if it does
//     );
// }

// module.exports = {
//     parseNVDData
// };
