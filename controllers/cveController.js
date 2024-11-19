const { createUnifiedModel } = require('../models/CVE');
const { createCVEModel } = require('../models/CVE');
const semver = require('semver');

const getUniqueVendors = async (db) => {
    const cveCollection = createCVEModel(db);
    const cveRecords = await cveCollection.find({}).toArray();

    const vendors = new Set();

    cveRecords.forEach(record => {
            if (record.cpe_data) {
            record.cpe_data.forEach(affected => {
                    if (affected.vendor) {
                    //vendors.add(affected.vendor.toLowerCase()); // Normalize to lowercase
                    vendors.add(affected.vendor.toLowerCase());
                    }
                    });
            }
            });

    //console.log("Unique vendors:" + Array.from(vendors)) ;
    return Array.from(vendors);
};

// Function to check if the given vendor exists in the CVE records
const vendorExistsInCVE = async (db, vendorName) => {
    const uniqueVendors = await getUniqueVendors(db);
    return uniqueVendors.some(vendor => vendor.includes(vendorName.toLowerCase()));
};

// Example of a route handler that uses this function
const checkVendor = async (db, vendorName) => {
    const exists = await vendorExistsInCVE(db, vendorName);
    return exists;
};
const filterByCVEId = async (db, cveId) => {
    const unifiedCollection = createUnifiedModel(db);
    return await unifiedCollection.findOne({ cve_id: cveId });
};

const getCveStatisticsByVendor = async (db, vendor) => {
    const unifiedCollection = createUnifiedModel(db);

    // Normalize vendor name for searching
    const normalizedVendor = vendor.replace(/\s+/g, '').toLowerCase();

    const cweTypeMapping = {
        'CWE-120': 'Overflow',
        'CWE-787': 'Memory Corruption',
        'CWE-89': 'SQL Injection',
        'CWE-79': 'XSS',
        'CWE-22': 'Directory Traversal',
        'CWE-98': 'File Inclusion',
        'CWE-352': 'CSRF',
        'CWE-611': 'XXE',
        'CWE-918': 'SSRF',
        'CWE-601': 'Open Redirect',
        'CWE-20': 'Input Validation',
    };

    // Aggregation to get CVE statistics
    const statistics = await unifiedCollection.aggregate([
        { 
            $match: { 
                'cpe.vendor': { $regex: normalizedVendor, $options: 'i' } // Match the vendor case-insensitively
            }
        },
        { 
            $unwind: '$weaknesses'  // Unwind the weaknesses array to access individual CWE IDs
        },
        {
            $match: {
                'weaknesses.cwe_id': { $in: Object.keys(cweTypeMapping) } // Filter for known CWE IDs
            }
        },
        {
            // Group by CVE ID to ensure we only count distinct CVEs
            $group: {
                _id: {
                    year: { $year: "$published_at" },  // Group by the year of publication
                    cweId: "$weaknesses.cwe_id",  // Group by CWE ID
                    cveId: "$cve_id"  // Group by CVE ID to ensure distinct counting
                }
            }
        },
        {
            // Now group by year and CWE ID to count distinct CVEs
            $group: {
                _id: { year: "$_id.year", cweId: "$_id.cweId" }, // Group by year and CWE ID
                count: { $sum: 1 }  // Count distinct CVEs for each CWE ID
            }
        },
        {
            // Group the results by year to compile the vulnerabilities
            $group: {
                _id: "$_id.year",
                vulnerabilities: {
                    $push: {
                        type: {
                            $cond: {
                                if: { $in: ["$_id.cweId", Object.keys(cweTypeMapping)] },
                                then: { $arrayElemAt: [Object.keys(cweTypeMapping), { $indexOfArray: [Object.keys(cweTypeMapping), "$_id.cweId"] }] },
                                else: "Other" // In case it doesn't match any predefined type
                            }
                        },
                        count: "$count"
                    }
                }
            }
        },
        {
            // Restructure the output to show vulnerabilities in key-value format
            $project: {
                _id: 1,
                vulnerabilities: {
                    $arrayToObject: {
                        $map: {
                            input: "$vulnerabilities",
                            as: "vuln",
                            in: {
                                k: "$$vuln.type",
                                v: "$$vuln.count"
                            }
                        }
                    }
                }
            }
        },
        { $sort: { _id: -1 } }  // Sort by year descending
    ]).toArray();

    return statistics;
};



const getCVEStats = async (db) => {
    const newAndUpdatedCVEs = {
        createdSinceYesterday: await getCVECount(db, { created_at: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
        updatedSinceYesterday: await getCVECount(db, { updated_at: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
        createdLast7Days: await getCVECount(db, { created_at: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
        updatedLast7Days: await getCVECount(db, { updated_at: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }),
        createdLast30Days: await getCVECount(db, { created_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
        updatedLast30Days: await getCVECount(db, { updated_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
    };

    const exploitedStats = await getExploitedVulnerabilitiesStats(db);

    return {
        newAndUpdatedCVEs,
        exploitedStats,
    };
};

// Function to count CVEs based on given criteria
const getCVECount = async (db, criteria) => {
    return await db.collection('unified_cves').countDocuments(criteria);
};

// Function to get statistics on known exploited vulnerabilities
const getExploitedVulnerabilitiesStats = async (db) => {
    const stats = {
        sinceYesterday: await getCVECount(db, {
            exploited: true,
            updated_at: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        }),
        last7Days: await getCVECount(db, {
            exploited: true,
            updated_at: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }),
        last30Days: await getCVECount(db, {
            exploited: true,
            updated_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        })
    };

    return stats;
};



// const getCvesByVendorAndYear = async (db, vendor, year, page = 1, limit = 20) => {
//     const unifiedCollection = createUnifiedModel(db);
    
//     // Normalize vendor name for searching
//     const normalizedVendor = vendor.replace(/\s+/g, '').toLowerCase();

//     // Pagination logic
//     const skip = (page - 1) * limit;

//     const cves = await unifiedCollection.aggregate([
//         { $unwind: '$cpe' },  // Unwind the cpe array
//         {
//             $addFields: {
//                 normalizedVendor: {
//                     $replaceAll: {
//                         input: { $toLower: { $replaceAll: { input: '$cpe.vendor', find: ' ', replacement: '' } } },
//                         find: '',
//                         replacement: ''
//                     }
//                 }
//             }
//         },
//         { $match: { normalizedVendor: normalizedVendor } },  // Match the normalized vendor name
//         { $match: { published_at: { $gte: new Date(`${year}-01-01`), $lt: new Date(`${year + 1}-01-01`) } } }, // Match the specified year
//         {
//             $group: {
//                 _id: '$cve_id',
//                 description: { $first: '$description' }  // Take the first description found
//             }
//         },
//         { $project: { cve_id: '$_id', description: 1 } },  // Project the final fields
//         { $skip: skip },  // Skip for pagination
//         { $limit: limit }  // Limit results
//     ]).toArray();

//     return cves;
// };

const getCvesByVendorAndYear = async (db, vendor, year, page = 1, limit = 20) => {
    const unifiedCollection = createUnifiedModel(db);
    
    // Normalize vendor name for searching
    const normalizedVendor = vendor.replace(/\s+/g, '').toLowerCase();

    // Pagination logic
    const skip = (page - 1) * limit;

    const cves = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },  // Unwind the cpe array
        {
            $addFields: {
                normalizedVendor: {
                    $replaceAll: {
                        input: { $toLower: { $replaceAll: { input: '$cpe.vendor', find: ' ', replacement: '' } } },
                        find: '',
                        replacement: ''
                    }
                }
            }
        },
        { $match: { normalizedVendor: normalizedVendor } },  // Match the normalized vendor name
        { $match: { published_at: { $gte: new Date(`${year}-01-01`), $lt: new Date(`${year + 1}-01-01`) } } }, // Match the specified year
        {
            $group: {
                _id: '$cve_id',
                description: { $first: '$description' },
                cvss_score: { $first: '$cvss_score' },
                epss_score: { $first: '$epss.epss_score' },
                published_at: { $first: '$published_at' },
                updated_at: { $first: '$updated_at' }
            }
        },
        { 
            $project: { 
                cve_id: '$_id', 
                description: 1,
                max_cvss: '$cvss_score',
                epss_score: '$epss_score',
                published: '$published_at',
                updated: '$updated_at'
            }
        },  // Project the final fields
        { $skip: skip },  // Skip for pagination
        { $limit: limit }  // Limit results
    ]).toArray();

    return cves;
};


const generalSearch = async (db, query) => {
    const unifiedCollection = createUnifiedModel(db);

    // Normalize the input query (e.g., remove spaces and lowercase)
    const normalizedQuery = query.replace(/\s+/g, '').toLowerCase();

    const searchQuery = {
        $or: [
            { cve_id: { $regex: query, $options: 'i' } },
            { description: { $regex: query, $options: 'i' } },
            { 'cpe.product': { $regex: query, $options: 'i' } },
            { 'cpe.vendor': { $regex: query, $options: 'i' } }
        ]
    };

    const results = await unifiedCollection.find(searchQuery).toArray();

    // Create a map to store distinct products and vendors (key: normalized value, value: original value)
    const productMap = new Map();
    const vendorMap = new Map();

    results.forEach(result => {
        result.cpe.forEach(cpeEntry => {
            // Normalize vendor and product names
            const normalizedVendor = cpeEntry.vendor ? cpeEntry.vendor.replace(/\s+/g, '').toLowerCase() : '';
            const normalizedProduct = cpeEntry.product ? cpeEntry.product.replace(/\s+/g, '').toLowerCase() : '';

            // Add to map if it doesn't already exist (only unique normalized keys are stored)
            if (normalizedVendor.includes(normalizedQuery) && !vendorMap.has(normalizedVendor)) {
                vendorMap.set(normalizedVendor, cpeEntry.vendor);  // Store the original vendor value
            }

            if (normalizedProduct.includes(normalizedQuery) && !productMap.has(normalizedProduct)) {
                productMap.set(normalizedProduct, cpeEntry.product);  // Store the original product value
            }
        });
    });

    // Convert maps back to arrays (containing only distinct values)
    const products = Array.from(productMap.values());
    const vendors = Array.from(vendorMap.values());

    return { products, vendors, cveIds: [] };
};

const getCvssScoreRanges = async (db) => {
    const scoreRanges = {
        "0-1": 0,
        "1-2": 0,
        "2-3": 0,
        "3-4": 0,
        "4-5": 0,
        "5-6": 0,
        "6-7": 0,
        "7-8": 0,
        "8-9": 0,
        "9+": 0
    };

    const vulnerabilities = await db.collection('unified_cves').find().toArray();

    vulnerabilities.forEach((vulnerability) => {
        const cvssScore = vulnerability.cvss_score; // Replace with the actual field name for CVSS score

        if (cvssScore >= 0 && cvssScore < 1) scoreRanges["0-1"]++;
        else if (cvssScore >= 1 && cvssScore < 2) scoreRanges["1-2"]++;
        else if (cvssScore >= 2 && cvssScore < 3) scoreRanges["2-3"]++;
        else if (cvssScore >= 3 && cvssScore < 4) scoreRanges["3-4"]++;
        else if (cvssScore >= 4 && cvssScore < 5) scoreRanges["4-5"]++;
        else if (cvssScore >= 5 && cvssScore < 6) scoreRanges["5-6"]++;
        else if (cvssScore >= 6 && cvssScore < 7) scoreRanges["6-7"]++;
        else if (cvssScore >= 7 && cvssScore < 8) scoreRanges["7-8"]++;
        else if (cvssScore >= 8 && cvssScore < 9) scoreRanges["8-9"]++;
        else if (cvssScore >= 9) scoreRanges["9+"]++;
    });

    // Calculate total count
    const totalCount = vulnerabilities.length;

    // Calculate weighted average
    let weightedSum = 0;
    vulnerabilities.forEach((vulnerability) => {
        weightedSum += vulnerability.cvss_score; // Add the CVSS score
    });

    const weightedAverage = totalCount > 0 ? (weightedSum / totalCount).toFixed(2) : 0; // Avoid division by zero

    return {
        scoreRanges,
        totalCount,
        weightedAverage
    };
};



const getVersionDetails = async (db, product, version) => {
    const unifiedCollection = createUnifiedModel(db);
    
    const versionDetails = await unifiedCollection.findOne({
        'cpe.product': product,
        'cpe.versions': { 
            $elemMatch: { 
                $or: [
                    { version: version },
                    { 
                        version: { $lte: version },
                        $or: [
                            { lessThan: { $gt: version } },
                            { lessThanOrEqual: { $gte: version } }
                        ]
                    }
                ]
            }
        }
    }, {
        projection: {
            'cpe': 1
        }
    });

    if (!versionDetails) {
        return null;
    }

    const cpe = versionDetails.cpe.find(c => c.product === product);
    const versionInfo = cpe.versions.find(v => 
        v.version === version || 
        (semver.lte(v.version, version) && 
         ((!v.lessThan || semver.gt(v.lessThan, version)) &&
          (!v.lessThanOrEqual || semver.gte(v.lessThanOrEqual, version))))
    );

    return {
        versionNames: [
            `${cpe.vendor} ${cpe.product} ${version}`,
            `cpe:2.3:a:${cpe.vendor.toLowerCase()}:${cpe.product.toLowerCase()}:${version}:*:*:*:*:*:*:*`,
            `cpe:/a:${cpe.vendor.toLowerCase()}:${cpe.product.toLowerCase()}:${version}`
        ],
        productInformation: {
            vendor: `https://www.${cpe.vendor.toLowerCase()}.com/`,
            product: `https://${cpe.product.toLowerCase()}.${cpe.vendor.toLowerCase()}.com/`
        },
        affectedRange: getVersionRange(versionInfo.version, versionInfo.lessThan, versionInfo.lessThanOrEqual)
    };
};




const compareVersions = (a, b) => {
    const cleanA = a.version.replace(/[^0-9.]/g, '');
    const cleanB = b.version.replace(/[^0-9.]/g, '');
    
    const partsA = cleanA.split('.').map(Number);
    const partsB = cleanB.split('.').map(Number);
    
    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
        const partA = partsA[i] || 0;
        const partB = partsB[i] || 0;
        if (partA > partB) return 1;
        if (partA < partB) return -1;
    }
    return 0;
};

const getProductVersions = async (db, product) => {
    const unifiedCollection = createUnifiedModel(db);
    
    const vulnerabilities = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },
        { $match: { 'cpe.product': product } },
        { $unwind: '$cpe.versions' },
        { $group: {
            _id: null,
            versions: { $addToSet: '$cpe.versions' },
            totalCount: { $sum: 1 }
        }}
    ]).toArray();

    if (vulnerabilities.length === 0 || vulnerabilities[0].versions.length === 0) {
        return [{
            version: 'All versions',
            vulnerabilityCount: await unifiedCollection.countDocuments({ 'cpe.product': product }),
            affectedRange: 'All versions'
        }];
    }

    const versions = vulnerabilities[0].versions;
    const totalCount = vulnerabilities[0].totalCount;

    // Process versions and create entries
    let processedVersions = versions.reduce((acc, v) => {
        if (v.version !== 'N/A' && v.version) {
            if (v.version.includes(' to ')) {
                // Handle range format "X.X to Y.Y"
                const [start, end] = v.version.split(' to ');
                acc.push({
                    version: start,
                    rangeEnd: end
                });
            } else {
                acc.push({
                    version: v.version,
                    lessThan: v.lessThan,
                    lessThanOrEqual: v.lessThanOrEqual
                });
            }
        } else if (v.lessThan) {
            // For entries with only lessThan, create two version entries
            const previousVersion = acc.length > 0 ? acc[acc.length - 1].version : '0.0.0';
            acc.push({
                version: previousVersion,
                lessThan: v.lessThan
            });
            acc.push({
                version: v.lessThan,
                isLessThan: true
            });
        }
        return acc;
    }, []);

    // Remove duplicates
    processedVersions = [...new Set(processedVersions.map(JSON.stringify))].map(JSON.parse);
    
    // Sort using custom comparison function
    processedVersions.sort(compareVersions);

    // Create final version entries
    return processedVersions.map((v, index, array) => {
        let affectedRange;
        if (v.isLessThan) {
            affectedRange = `< ${v.version}`;
        } else if (v.rangeEnd) {
            affectedRange = `${v.version} to ${v.rangeEnd}`;
        } else {
            affectedRange = getVersionRange(v.version, v.lessThan, v.lessThanOrEqual);
        }

        return {
            version: v.version,
            vulnerabilityCount: totalCount, // We don't have individual counts, so using total
            affectedRange: affectedRange
        };
    });
};

// Update getVersionRange function to handle non-standard version formats
const getVersionRange = (version, lessThan, lessThanOrEqual) => {
    if (version === 'N/A') {
        return 'All versions';
    }
    let range = `>= ${version}`;
    if (lessThan) {
        range += ` < ${lessThan}`;
    } else if (lessThanOrEqual) {
        range += ` <= ${lessThanOrEqual}`;
    }
    return range;
};

const getProductVersionVulnerabilities = async (db, product, version) => {
    const unifiedCollection = createUnifiedModel(db);
    
    // First, get the product versions to determine the correct range
    const productVersions = await getProductVersions(db, product);
    
    // Find the current version entry
    const currentVersionEntry = productVersions.find(v => v.version === version);
    
    if (!currentVersionEntry) {
        return []; // No vulnerabilities if the version doesn't exist
    }

    let match;
    if (currentVersionEntry.affectedRange === 'All versions') {
        match = { 'cpe.product': product };
    } else if (currentVersionEntry.affectedRange.startsWith('<')) {
        // For "less than" versions, we need to get all vulnerabilities up to this version
        const lessThanVersion = currentVersionEntry.affectedRange.split(' ')[1];
        match = { 
            'cpe.product': product,
            $or: [
                { 'cpe.versions.version': 'N/A' },
                { 'cpe.versions.version': { $lt: lessThanVersion } },
                { 'cpe.versions.lessThan': { $gt: version } },
                { 'cpe.versions.lessThanOrEqual': { $gte: version } }
            ]
        };
    } else if (currentVersionEntry.affectedRange.includes(' to ')) {
        // For range versions "X.X to Y.Y"
        const [rangeStart, rangeEnd] = currentVersionEntry.affectedRange.split(' to ');
        match = {
            'cpe.product': product,
            $or: [
                { 'cpe.versions.version': { $regex: `^${rangeStart} to ${rangeEnd}$` } },
                {
                    $and: [
                        { 'cpe.versions.version': { $gte: rangeStart } },
                        { 'cpe.versions.version': { $lte: rangeEnd } }
                    ]
                }
            ]
        };
    } else {
        // For regular versions, use the original logic
        match = { 
            'cpe.product': product,
            $or: [
                { 'cpe.versions.version': version },
                { 
                    'cpe.versions.version': { $lte: version }, 
                    $or: [
                        { 'cpe.versions.lessThan': { $gt: version } },
                        { 'cpe.versions.lessThanOrEqual': { $gte: version } }
                    ]
                }
            ]
        };
    }

    const vulnerabilities = await unifiedCollection.aggregate([
        { $match: match },
        { $unwind: '$cpe' },
        { $unwind: '$cpe.versions' },
        { $group: {
            _id: '$cve_id',
            description: { $first: '$description' },
            cvss_score: { $first: '$cvss_score' },
            epss_score: { $first: '$epss.epss_score' },
            published_at: { $first: '$published_at' },
            updated_at: { $first: '$updated_at' }
        }}
    ]).toArray();

    return vulnerabilities.map(v => ({
        cve_id: v._id,
        description: v.description,
        max_cvss: v.cvss_score,
        epss_score: v.epss_score,
        published: v.published_at,
        updated: v.updated_at
    }));
};

const getFilteredProductVulnerabilities = async (db, product, version, page = 1, limit = 20, filters = {}) => {
    const unifiedCollection = createUnifiedModel(db);
    const skip = (page - 1) * limit;

    // First, get the product versions to determine the correct range
    const productVersions = await getProductVersions(db, product);
    
    // Find the current version entry
    const currentVersionEntry = productVersions.find(v => {
        if (version.includes(' to ')) {
            // For range versions, match the exact range
            return v.affectedRange === version;
        } else if (version.startsWith('< ')) {
            // For "less than" versions, match the exact "less than" range
            return v.affectedRange === version;
        }
        return v.version === version;
    });

    if (!currentVersionEntry) {
        return {
            vulnerabilities: [],
            pagination: {
                total: 0,
                page,
                limit,
                pages: 0
            }
        };
    }

    // Base match criteria
    let match = { 'cpe.product': product };

    // Add version-specific matching logic
    if (currentVersionEntry.affectedRange === 'All versions') {
        // No additional version criteria needed
    } else if (currentVersionEntry.affectedRange.startsWith('< ')) {
        const lessThanVersion = currentVersionEntry.affectedRange.split(' ')[1];
        match.$or = [
            { 'cpe.versions.version': 'N/A' },
            { 'cpe.versions.version': { $lt: lessThanVersion } },
            { 'cpe.versions.lessThan': { $gt: version } },
            { 'cpe.versions.lessThanOrEqual': { $gte: version } }
        ];
    } else if (currentVersionEntry.affectedRange.includes(' to ')) {
        const [rangeStart, rangeEnd] = currentVersionEntry.affectedRange.split(' to ').map(v => v.trim());
        match.$or = [
            { 'cpe.versions.version': currentVersionEntry.affectedRange }, // Exact range match
            {
                $and: [
                    { 'cpe.versions.version': { $gte: rangeStart } },
                    { 'cpe.versions.version': { $lte: rangeEnd } }
                ]
            },
            {
                'cpe.versions.version': { $lte: rangeEnd },
                'cpe.versions.lessThan': { $gt: rangeStart }
            }
        ];
    } else {
        // For regular versions
        match.$or = [
            { 'cpe.versions.version': version },
            {
                'cpe.versions.version': { $lte: version },
                $or: [
                    { 'cpe.versions.lessThan': { $gt: version } },
                    { 'cpe.versions.lessThanOrEqual': { $gte: version } }
                ]
            }
        ];
    }

    // Add date filters
    if (filters.year || filters.month) {
        const dateFilter = {};
        if (filters.year) {
            dateFilter.$gte = new Date(`${filters.year}-01-01T00:00:00.000Z`);
            dateFilter.$lt = new Date(`${parseInt(filters.year) + 1}-01-01T00:00:00.000Z`);
        }
        if (filters.month) {
            const startDate = new Date(`${filters.year}-${filters.month}-01T00:00:00.000Z`);
            const endDate = new Date(startDate);
            endDate.setMonth(startDate.getMonth() + 1);
            dateFilter.$gte = startDate;
            dateFilter.$lt = endDate;
        }
        match.published_at = dateFilter;
    }

    // Add CVSS score filter
    if (filters.minCvss) {
        match.cvss_score = { $gte: parseFloat(filters.minCvss) };
    }

    // Determine sort field and direction
    let sortField = { published_at: -1 }; // default sort
    if (filters.sortBy) {
        const [field, direction] = filters.sortBy.split(':');
        const sortDirection = direction === 'asc' ? 1 : -1;
        
        switch (field) {
            case 'publishDate':
                sortField = { published_at: sortDirection };
                break;
            case 'updateDate':
                sortField = { updated_at: sortDirection };
                break;
            case 'cveId':
                sortField = { cve_id: sortDirection };
                break;
            case 'cvssScore':
                sortField = { cvss_score: sortDirection };
                break;
            case 'epssScore':
                sortField = { 'epss.epss_score': sortDirection };
                break;
        }
    }

    // Get total count for pagination
    const total = await unifiedCollection.countDocuments(match);

    const pipeline = [
        { $match: match },
        { $sort: sortField },
        { $skip: skip },
        { $limit: limit },
        { $project: {
            cve_id: 1,
            description: 1,
            cvss_score: 1,
            'epss.epss_score': 1,
            published_at: 1,
            updated_at: 1
        }}
    ];

    const vulnerabilities = await unifiedCollection.aggregate(pipeline).toArray();

    return {
        vulnerabilities,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };
};


const getFilteredVendorVulnerabilities = async (db, vendor, year, page = 1, limit = 20, filters = {}) => {
    const unifiedCollection = createUnifiedModel(db);
    const skip = (page - 1) * limit;
    
    // Base match criteria
    let match = { 
        'cpe.vendor': vendor,
        published_at: {
            $gte: new Date(`${year}-01-01`),
            $lt: new Date(`${parseInt(year) + 1}-01-01`)
        }
    };

    // Add month filter if provided
    if (filters.month) {
        const startDate = new Date(`${year}-${filters.month}-01T00:00:00.000Z`);
        const endDate = new Date(startDate);
        endDate.setMonth(startDate.getMonth() + 1);
        match.published_at = {
            $gte: startDate,
            $lt: endDate
        };
    }

    // Add CVSS score filter
    if (filters.minCvss) {
        match.cvss_score = { $gte: parseFloat(filters.minCvss) };
    }

    // Determine sort field and direction
    let sortField = { published_at: -1 }; // default sort
    if (filters.sortBy) {
        const [field, direction] = filters.sortBy.split(':');
        const sortDirection = direction === 'asc' ? 1 : -1;
        
        switch (field) {
            case 'publishDate':
                sortField = { published_at: sortDirection };
                break;
            case 'updateDate':
                sortField = { updated_at: sortDirection };
                break;
            case 'cveId':
                sortField = { cve_id: sortDirection };
                break;
            case 'cvssScore':
                sortField = { cvss_score: sortDirection };
                break;
            case 'epssScore':
                sortField = { 'epss.epss_score': sortDirection };
                break;
        }
    }

    const pipeline = [
        { $match: match },
        { $sort: sortField },
        { $skip: skip },
        { $limit: limit },
        { $project: {
            cve_id: 1,
            description: 1,
            cvss_score: 1,
            'epss.epss_score': 1,
            published_at: 1,
            updated_at: 1
        }}
    ];

    // Get total count for pagination
    const total = await unifiedCollection.countDocuments(match);
    const vulnerabilities = await unifiedCollection.aggregate(pipeline).toArray();

    return {
        vulnerabilities,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };
};


// create a function for getting the unique vendors from the database and return them as a response to the client alphabetically sorted in ascending order 
// (i.e., from A to Z).
// New functions to add to your existing code

const getAlphabeticalVendors = async (db, letter, page = 1, limit = 20) => {
    const unifiedCollection = createUnifiedModel(db);
    const skip = (page - 1) * limit;
    
    // Create match condition based on whether a letter is provided
    const matchCondition = letter ? 
        { 'cpe.vendor': { $regex: `^${letter}`, $options: 'i' } } : 
        {};

    // Get total count for pagination
    const totalCount = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },
        { $match: matchCondition },
        { $group: { _id: '$cpe.vendor' } },
        { $count: 'total' }
    ]).toArray();

    const total = totalCount[0]?.total || 0;

    // Get paginated vendors with product count
    const vendors = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },
        { $match: matchCondition },
        {
            $group: {
                _id: '$cpe.vendor',
                vulnerabilityCount: { $sum: 1 },
                latestUpdate: { $max: '$updated_at' },
                uniqueProducts: { $addToSet: '$cpe.product' }
            }
        },
        { $sort: { '_id': 1 } },
        { $skip: skip },
        { $limit: limit },
        {
            $project: {
                vendor: '$_id',
                vulnerabilityCount: 1,
                lastUpdated: '$latestUpdate',
                productCount: { $size: '$uniqueProducts' },
                _id: 0
            }
        }
    ]).toArray();

    return {
        vendors,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };
};
const getAlphabeticalProducts = async (db, letter, page = 1, limit = 20) => {
    const unifiedCollection = createUnifiedModel(db);
    const skip = (page - 1) * limit;
    
    // Create match condition based on whether a letter is provided
    const matchCondition = letter ? 
        { 'cpe.product': { $regex: `^${letter}`, $options: 'i' } } : 
        {};

    // Get total count for pagination
    const totalCount = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },
        { $match: matchCondition },
        { $group: { _id: '$cpe.product' } },
        { $count: 'total' }
    ]).toArray();

    const total = totalCount[0]?.total || 0;

    // Get paginated products
    const products = await unifiedCollection.aggregate([
        { $unwind: '$cpe' },
        { $match: matchCondition },
        {
            $group: {
                _id: '$cpe.product',
                vendor: { $first: '$cpe.vendor' },
                count: { $sum: 1 },
                latestUpdate: { $max: '$updated_at' }
            }
        },
        { $sort: { '_id': 1 } },
        { $skip: skip },
        { $limit: limit },
        {
            $project: {
                product: '$_id',
                vendor: 1,
                vulnerabilityCount: '$count',
                lastUpdated: '$latestUpdate',
                _id: 0
            }
        }
    ]).toArray();

    return {
        products,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };
};


module.exports = {
    filterByCVEId,
    generalSearch,
    getCveStatisticsByVendor,
    getCvesByVendorAndYear,
    getCVEStats,
    getCvssScoreRanges,
    getProductVersions,
    getProductVersionVulnerabilities,
    getVersionDetails,
    getFilteredProductVulnerabilities,
    getFilteredVendorVulnerabilities,
    getUniqueVendors,
    vendorExistsInCVE,
    checkVendor,
    getAlphabeticalVendors,
    getAlphabeticalProducts
};
