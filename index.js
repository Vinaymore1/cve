const express = require('express');
const { checkGitDiff } = require('./services/gitdiff'); // Import checkGitDiff
const { parseCVEData } = require('./services/mitreService'); // Import parseCVEData
const { parseCVEMapData, processChangedFilesCvemap}  = require('./services/cvemapService');
const { cloneOrPullRepo } = require('./services/git'); // Import parseCVEMapData
const { parseNVDData } = require('./services/nvdServices'); // Import parseNVDData
const { parseUnifiedData } = require('./services/unified'); // Import parseUnifiedData
const connectDB = require('./config/db');
const cveRoutes = require('./routes/cveRoutes');
const cron = require('node-cron'); // Import cron
const authRoutes = require('./server/api/auth'); 
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173'
  }));

(async () => {
    try {
        const db = await connectDB();
        console.log("Connected to MongoDB");

        app.use('/api/cve', cveRoutes); 
        app.use('/api/auth', authRoutes); 

        // await cloneOrPullRepo();
        // const changedFiles = await checkGitDiff();
        // await processChangedFilesCvemap('.tmp/input', db);
        // await parseCVEMapData(db); 

        // cron.schedule('*/3 * * * *', async () => {
        //     console.log('Running MITRE data processing and Git diff check...');
            
        //     try {
        //         // Check for Git differences
        //         const changedFiles = await checkGitDiff();
                
        //         // If there are changed files, parse CVE data
        //         if (changedFiles.length > 0) {
        //             // console.log(`Processing changed files: ${changedFiles}`);
        //             console.log(`Processing changed files`);
                    // await parseCVEData(db, changedFiles);  // Pass the changed files
        //         } else {
        //             console.log('No changes detected in Git. Skipping CVE parsing.');
        //         }

        //         console.log('MITRE and Git diff processing completed.');
        //     } catch (error) {
        //         console.error('Error during scheduled job:', error);
        //     }
        // });

        // cron.schedule('*/2 * * * *', async () => {
        //     console.log('Running NVD data parsing...');
            
        //     try {
        //         await parseNVDData(db);
        //         console.log('NVD data parsing completed successfully.');
        //     } catch (error) {
        //         console.error('Error during NVD data parsing:', error);
        //     }
        // });

        // await parseCVEMapData(db); 
        
        // await parseUnifiedData(db);

        app.listen(PORT, () => {
            console.log(`Application initialized successfully on port ${PORT}`);
        });
    } catch (error) {
        console.error("Error initializing the application:", error);
    }
})();





// const express = require('express');
// const { checkGitDiff } = require('./services/gitdiff'); // Import checkGitDiff
// const { cloneOrPullRepo } = require('./services/git');
// const { parseCVEData } = require('./services/mitreService');
// const { parseCVEMapData } = require('./services/cvemapService');
// const {parseNVDData} = require('./services/nvdServices');
// const { parseUnifiedData } = require('./services/unified');
// const connectDB = require('./config/db');

// const app = express();
// const PORT = process.env.PORT || 3000;

// (async () => {
//     try {
//         const db = await connectDB();
//         console.log("Connected to MongoDB");

        
//         // await cloneOrPullRepo();
//         const changedFiles = await checkGitDiff();

//         await parseCVEData(db, changedFiles);
//         await parseCVEMapData(db); 
//         await parseNVDData(db);
//         await parseUnifiedData(db);

//         app.listen(PORT, () => {
//             console.log(`Application initialized successfully on port ${PORT}`);
//         });
//     } catch (error) {
//         console.error("Error initializing the application:", error);
//     }
// })();


