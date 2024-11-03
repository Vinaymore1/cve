// server/index.js
const express = require('express');
const { checkGitDiff } = require('./services/gitdiff');
const { parseCVEData } = require('./services/mitreService');
const { parseCVEMapData, processChangedFilesCvemap } = require('./services/cvemapService');
const { cloneOrPullRepo } = require('./services/git');
const { parseNVDData } = require('./services/nvdServices');
const { parseUnifiedData } = require('./services/unified');
const connectDB = require('./config/db');
const cveRoutes = require('./routes/cveRoutes');
const cron = require('node-cron'); // Import cron

const app = express();
const PORT = process.env.PORT || 3000;

(async () => {
    try {
        const db = await connectDB();
        console.log("Connected to MongoDB");

        // Add express body parser middleware
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));

        // Use authentication routes
        app.use('/api/auth', require('./api/auth'));

        // Use CVE routes, protected by the auth middleware
        app.use('/api/cve', cveRoutes);

        // Run cron jobs, Git diffs, and data processing tasks (kept the same)
        // Uncomment your cron jobs here...

        app.listen(PORT, () => {
            console.log(`Application initialized successfully on port ${PORT}`);
        });
    } catch (error) {
        console.error("Error initializing the application:", error);
    }
})();
