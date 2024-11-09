const express = require('express');
const router = express.Router();
const {
    addVendorToWatchlist,
    getWatchlist,
    removeFromWatchlist
} = require('../controllers/watchlistController');

const connectDB = require('../config/db');

const MAX_WATCHLIST_SIZE = 10;


// POST route to add a vendor to the watchlist
router.post('/watchlist', async (req, res) => {
    try {
    const db = await connectDB();
    const { username, vendor } = req.body;
    console.log ("Connected to db") ;

    if (!username || !vendor) {
    return res.status(400).json({ message: 'Username and vendor are required.' });
    }

    const existingUser = await getWatchlist(db, username);
    console.log ("error") ;
    if (existingUser) {
        // Check current size of the watching array
        if (existingUser.watching.length >= MAX_WATCHLIST_SIZE) {
        return res.status(400).json({ message: `Cannot add more than ${MAX_WATCHLIST_SIZE} vendors to the watchlist.` });
        } else {
            const result = await addVendorToWatchlist(db, username, vendor);
            res.status(200).json(result);
            } 
    }else {
        const result = await addVendorToWatchlist(db, username, vendor);
        res.status(200).json(result);
        } 
    } catch (err) {
        if (err.message.includes('Vendor')) {
            return res.status(400).json({ message: err.message });
        }
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
        }

});


// Route to get the user's watchlist
router.get('/watchlist/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const db = await connectDB();
        const watchlist = await getWatchlist(db, username);
        if (watchlist) {
            res.json(watchlist);
        } else {
            res.status(404).json({ message: 'Watchlist not found.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Route to remove a vendor from the user's watchlist
router.delete('/watchlist', async (req, res) => {
    const { username, vendor } = req.body;
    if (!username || !vendor) {
        return res.status(400).json({ message: 'Username and vendor are required.' });
    }

    try {
        const db = await connectDB();
        await removeFromWatchlist(db, username, vendor);
        res.status(200).json({ message: 'Vendor removed from watchlist.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

module.exports = router;

