const express = require('express');
const router = express.Router();
const { 
    filterByCVEId, 
    generalSearch, 
    getCveStatisticsByVendor, 
    getCvesByVendorAndYear, 
    getCVEStats,
    getCvssScoreRanges,
    getProductVersions,
    getProductVersionVulnerabilities,
    getVersionDetails,
    getFilteredVendorVulnerabilities,
    getFilteredProductVulnerabilities,
    getUniqueVendors,
    getAlphabeticalVendors,
    getAlphabeticalProducts
} = require('../controllers/cveController'); 
const connectDB = require('../config/db'); 
const authMiddleware = require('../server/middleware/auth'); 

// Add route to get unique vendors 
router.get('/vendors', async (req, res) => {
    try {
        const db = await connectDB();
        const vendors = await getUniqueVendors(db);
        res.json(vendors);
    } catch (err) {
        console.error(err); 
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
// Route to filter by CVE ID (protected route)
router.get('/cveid/:id' , async (req, res) => {
    try {
        const db = await connectDB();
        const cve = await filterByCVEId(db, req.params.id);
        if (cve) {
            res.json(cve);
        } else {
            res.status(404).json({ message: 'CVE not found' });
        }
    } catch (err) {
        console.error(err); 
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to get CVE statistics by vendor (protected route)
router.get('/statistics/:vendor',  async (req, res) => {
    try {
        const db = await connectDB();
        const { vendor } = req.params;
        const statistics = await getCveStatisticsByVendor(db, vendor);
        res.json(statistics);
    } catch (err) {
        console.error(err); // Log the error for debugging
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to get CVEs by vendor and year (protected route)
router.get('/vendor/:vendor/year/:year', async (req, res) => {
    try {
        const db = await connectDB();
        const { vendor, year } = req.params;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;

        const cves = await getCvesByVendorAndYear(db, vendor, year, page, limit);
        res.json(cves);
    } catch (err) {
        console.error(err); 
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to get CVE statistics (public route)
router.get('/stats', async (req, res) => {
    try {
        const db = await connectDB();
        const stats = await getCVEStats(db);
        res.json(stats);
    } catch (err) {
        console.error(err); // Log the error for debugging
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Autocomplete route (protected route)
router.get('/autocomplete',  async (req, res) => {
    try {
        const db = await connectDB();
        const query = req.query.q || '';
        if (!query) {
            return res.json({ products: [], vendors: [], cveIds: [] });
        }

        const results = await generalSearch(db, query);
        res.json(results);
    } catch (err) {
        console.error(err); 
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.get('/cvss/stats',  async (req, res) => {
    try {
        const db = await connectDB();
        const cvssStats = await getCvssScoreRanges(db);
        res.json(cvssStats);
    } catch (err) {
        console.error(err); 
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.get('/product/:product/versions',  async (req, res) => {
    try {
        const db = await connectDB();
        const { product } = req.params;
        const versions = await getProductVersions(db, product);
        if (versions.length === 0) {
            res.status(404).json({ message: 'No versions found for this product' });
        } else {
            res.json(versions);
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to get vulnerabilities for a specific product and version (protected route)
router.get('/product/:product/version/:version/vulnerabilities',  async (req, res) => {
    try {
        const db = await connectDB();
        const { product, version } = req.params;
        const vulnerabilities = await getProductVersionVulnerabilities(db, product, version);
        if (vulnerabilities.length === 0) {
            res.status(404).json({ message: 'No vulnerabilities found for this product and version' });
        } else {
            res.json(vulnerabilities);
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to get version details (protected route)
router.get('/product/:product/version/:version/details',  async (req, res) => {
    try {
        const db = await connectDB();
        const { product, version } = req.params;
        const details = await getVersionDetails(db, product, version);
        if (details) {
            res.json(details);
        } else {
            res.status(404).json({ message: 'Version details not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.get('/product/:product/version/:version/filtered', async (req, res) => {
    try {
        const db = await connectDB();
        // Decode the URL-encoded product name and version
        const product = decodeURIComponent(req.params.product);
        const version = decodeURIComponent(req.params.version);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        
        const filters = {
            year: req.query.year,
            month: req.query.month,
            minCvss: req.query.minCvss,
            sortBy: req.query.sortBy
        };

        const result = await getFilteredProductVulnerabilities(
            db, 
            product, 
            version, 
            page,
            limit,
            filters
        );
        
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
// router.get('/product/:product/version/:version/filtered', async (req, res) => {
//     try {
//         const db = await connectDB();
//         const { product, version } = req.params;
//         const filters = {
//             year: req.query.year,
//             month: req.query.month,
//             minCvss: req.query.minCvss,
//             sortBy: req.query.sortBy // format: "field:direction" (e.g., "publishDate:desc")
//         };

//         const vulnerabilities = await getFilteredProductVulnerabilities(db, product, version, filters);
//         res.json(vulnerabilities);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Server error', error: err.message });
//     }
// });

// Route for filtered vendor vulnerabilities
router.get('/vendor/:vendor/year/:year/filtered', async (req, res) => {
    try {
        const db = await connectDB();
        const { vendor, year } = req.params;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const filters = {
            month: req.query.month,
            minCvss: req.query.minCvss,
            sortBy: req.query.sortBy 
        };

        const result = await getFilteredVendorVulnerabilities(db, vendor, year, page, limit, filters);
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});


router.get('/vendors/alphabetical/:letter?', async (req, res) => {
    try {
        const { letter } = req.params;
        const db = await connectDB();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        
        const vendors = await getAlphabeticalVendors(db, letter, page, limit);
        res.json(vendors);
    } catch (error) {
        console.error('Error fetching vendors:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/products/alphabetical/:letter?', async (req, res) => {
    try {
        const { letter } = req.params;
        const db = await connectDB();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        
        const products = await getAlphabeticalProducts(db, letter, page, limit);
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;



