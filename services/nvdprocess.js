const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const zlib = require('zlib');
const { createWriteStream, createReadStream } = require('fs'); // Added createReadStream import

const nvdPath = path.join(__dirname, '../nvd'); // Path to the NVD data folder

// Create NVD folder if it doesn't exist
async function ensureNvdFolderExists() {
    await fs.mkdir(nvdPath, { recursive: true });
}

// Function to download and unzip the NVD JSON files
async function downloadAndUnzipNVD(year) {
    const url = `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${year}.json.gz`;
    const filePath = path.join(nvdPath, `nvdcve-1.1-${year}.json.gz`);
    const outputFilePath = path.join(nvdPath, `nvdcve-1.1-${year}.json`);

    try {
        // Download the gzipped file
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        await fs.writeFile(filePath, response.data);

        // Unzip the file
        const gzip = zlib.createGunzip();
        const inputStream = createReadStream(filePath); // Corrected here
        const outputStream = createWriteStream(outputFilePath);

        inputStream.pipe(gzip).pipe(outputStream);

        return new Promise((resolve, reject) => {
            outputStream.on('finish', () => {
                console.log(`Successfully downloaded and unzipped ${year} data.`);
                resolve();
            });

            outputStream.on('error', (err) => {
                console.error(`Error unzipping ${year} data:`, err);
                reject(err);
            });
        });
    } catch (error) {
        console.error(`Failed to download data for ${year}:`, error.message);
    }
}

// Main function to download data for all years from 2002 to 2024
async function downloadNVDData() {
    await ensureNvdFolderExists();

    const years = Array.from({ length: 23 }, (_, i) => (2002 + i)).concat(2024); // Generates array [2002, ..., 2024]

    for (const year of years) {
        await downloadAndUnzipNVD(year);
    }
}

// Execute the download process
downloadNVDData().catch(console.error);
