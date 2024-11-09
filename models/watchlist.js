const { ObjectId } = require('mongodb');



const watchlistSchema = {
    _id: ObjectId,
    username: { type: String, required: true },
    watching: { type: [String], default: [] }
};

const createWatchlistModel = (db) => {
    return db.collection('watchlist');
};

module.exports = {
    createWatchlistModel,
    watchlistSchema
};

