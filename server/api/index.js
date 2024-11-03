// server/api/index.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const authMiddleware = require('../middleware/auth');

const router = express.Router({ mergeParams: true });

// Mount the auth routes (registration, login) without middleware
router.use('/auth', require('./auth'));

// Get the absolute path of the current directory
const currentDir = __dirname;

// Read all subdirectories in the current directory
const subdirectories = fs.readdirSync(currentDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory() && dirent.name !== 'auth')
    .map(dirent => dirent.name);

// Protect all routes except auth with the auth middleware
router.use(authMiddleware);

// Dynamically mount routers for each subdirectory
subdirectories.forEach(subdirectory => {
    const subdirectoryPath = path.join(currentDir, subdirectory);
    const subdirectoryRouter = require(subdirectoryPath);
    router.use(`/${subdirectory}`, subdirectoryRouter);
});

module.exports = router;
