// cron/cronJobs.js
const cron = require('node-cron');
const { cloneOrUpdateMITRERepo, parseCVEData } = require('../services/mitreService');
const connectDB = require('../config/db');

async function setupCronJobs() {
    const db = await connectDB();

    // Set up a daily job to pull from MITRE and update the database
    cron.schedule('0 0 * * *', async () => {
        console.log("Running daily MITRE update...");
        cloneOrUpdateMITRERepo();
        parseCVEData(db);
    });
}

module.exports = setupCronJobs;
