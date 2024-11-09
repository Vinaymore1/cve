const { createWatchlistModel } = require('../models/watchlist');
const { vendorExistsInCVE } = require('./cveController'); // Ensure this function checks if vendor exists
const addVendorToWatchlist = async (db, username, vendor) => {
    const watchlistCollection = createWatchlistModel(db);

    // Check if the vendor exists in CVE records
    const vendorExists = await vendorExistsInCVE(db, vendor);
    if (!vendorExists) {
        throw new Error(`Vendor "${vendor}" does not exist in the CVE records.`);
    }

    // Check if the user exists, create if not
    const userWatchlist = await watchlistCollection.findOne({ username });
    if (!userWatchlist) {
        // Create a new watchlist entry for the user
        await watchlistCollection.insertOne({ username, watching: [vendor] });
        return { message: `New user "${username}" created and vendor "${vendor}" added to watchlist.` };
    } else {
        // User exists, add the vendor to their watchlist
        const result = await watchlistCollection.findOneAndUpdate(
            { username },
            { $addToSet: { watching: vendor } }, // Use $addToSet to avoid duplicates
            { returnDocument: 'after' }
        );
        return {
            message: `Vendor "${vendor}" added to watchlist for user "${username}".`,
            watchlist: result.value
        };
    }
};



const getWatchlist = async (db, username) => {
    const watchlistCollection = createWatchlistModel(db);
    return await watchlistCollection.findOne({ username });
};

const removeFromWatchlist = async (db, username, vendor) => {
    const watchlistCollection = createWatchlistModel(db);
    return await watchlistCollection.updateOne(
        { username },
        { $pull: { watching: vendor } }
    );
};

module.exports = {
    addVendorToWatchlist,
    getWatchlist,
    removeFromWatchlist
};

