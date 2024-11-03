const { MongoClient } = require('mongodb');
require('dotenv').config();  // Load .env variables

const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/cve-database';  // Use default if not in env

if (!mongoURI) {
  console.error("MongoDB connection string is missing!");
  process.exit(1);
}

const client = new MongoClient(mongoURI);  // No need for useNewUrlParser and useUnifiedTopology

async function connectDB() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    return client.db(); // Return the database object for further use
  } catch (err) {
    console.error('Error connecting to MongoDB:', err);
    process.exit(1);
  }
}

module.exports = connectDB;
