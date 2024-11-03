const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createUserModel } = require('../../../models/users'); // Adjust import as needed
const router = express.Router();
const connectDB = require('../../../config/db'); // Import the database connection

let db; // Declare a variable to hold the database connection

// Establish a connection to the database
connectDB().then(database => {
    db = database; // Assign the connected database to the db variable
});

// Define a route for user registration
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const usersCollection = createUserModel(db); // Get the users collection

        // Check if the user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user object
        const newUser = {
            name,
            email,
            password: hashedPassword,
            createdAt: new Date(), // Set createdAt to the current date
        };

        // Insert the new user into the database
        await usersCollection.insertOne(newUser);

        // Create and send a JWT token
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

        res.status(201).json({ message: 'User registered successfully', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Define a route for user login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const secretKey = process.env.JWT_SECRET_KEY;

    try {
        const usersCollection = createUserModel(db); // Get the users collection

        // Find the user by email
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Check the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Generate the JWT token
        const payload = {
            userId: user._id,
            name: user.name,
            email: user.email,
        };

        const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;




// // server/api/auth/index.js
// const express = require('express');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const User = require('../../../models/users'); // Import User model
// const router = express.Router();

// // Define a route for user registration
// router.post('/register', async (req, res) => {
//     const { name, email, password } = req.body;

//     try {
//         // Check if the user already exists
//         const existingUser = await User.findOne({ email });
//         if (existingUser) {
//             return res.status(400).json({ error: 'User already exists' });
//         }

//         // Hash the password before saving
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Create a new user
//         const newUser = new User({
//             name,
//             email,
//             password: hashedPassword
//         });

//         await newUser.save();

//         // Create and send a JWT token
//         const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

//         res.status(201).json({ message: 'User registered successfully', token });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// // Define a route for user login
// router.post('/login', async (req, res) => {
//     const { email, password } = req.body;
//     const secretKey = process.env.JWT_SECRET_KEY;

//     try {
//         // Find the user by email
//         const user = await User.findOne({ email });
//         if (!user) {
//             return res.status(400).json({ msg: 'Invalid credentials' });
//         }

//         // Check the password
//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) {
//             return res.status(400).json({ msg: 'Invalid credentials' });
//         }

//         // Generate the JWT token
//         const payload = {
//             userId: user._id,
//             name: user.name,
//             email: user.email
//         };

//         const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

//         res.json({ token });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// module.exports = router;
