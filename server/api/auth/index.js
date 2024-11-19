const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer'); // For sending OTP emails
const crypto = require('crypto'); // For generating OTP
const { createUserModel } = require('../../../models/users'); 
const router = express.Router();
const connectDB = require('../../../config/db');
const sendEmail = require('../auth/mail');
let db;

// Establish database connection
connectDB().then(database => {
    db = database;
});


// Route for registration with email OTP verification
router.post('/register', async (req, res) => {
    const { name, email, password, otp } = req.body;

    try {
        const usersCollection = createUserModel(db);

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const otpRecord = await db.collection('otps').findOne({ email, otp });
        if (!otpRecord || otpRecord.expiry < Date.now()) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            name,
            email,
            password: hashedPassword,
            createdAt: new Date(),
        };

        await usersCollection.insertOne(newUser);
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
        res.status(201).json({ message: 'User registered successfully', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to request OTP for registration
// Route to request OTP for registration
router.post('/request-otp', async (req, res) => {
    const { email } = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();

    try {
        // Save OTP in DB
        await db.collection('otps').updateOne(
            { email },
            { $set: { otp, expiry: Date.now() + 10 * 60 * 1000 } },
            { upsert: true }
        );

        // Send OTP email
        await sendEmail(email, 'Your OTP for Registration', `Your OTP is ${otp}`);
        res.status(200).json({ message: 'OTP sent to email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Route for login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const secretKey = process.env.JWT_SECRET_KEY;

    try {
        const usersCollection = createUserModel(db);
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route for logout
router.post('/logout', (req, res) => {
    res.status(200).json({ message: 'Logged out successfully' });
    // Consider token invalidation for persistent storage if needed
});

// Route to request OTP for forgot password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();

    try {
        const user = await db.collection('users').findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Email not found' });
        }

        await db.collection('otps').updateOne(
            { email },
            { $set: { otp, expiry: Date.now() + 10 * 60 * 1000 } },
            { upsert: true }
        );

        await sendEmail(email, 'OTP for Password Reset', `Your OTP is ${otp}`);
        res.status(200).json({ message: 'OTP sent to email' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route for resetting password
router.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const otpRecord = await db.collection('otps').findOne({ email, otp });
        if (!otpRecord || otpRecord.expiry < Date.now()) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.collection('users').updateOne(
            { email },
            { $set: { password: hashedPassword } }
        );

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;


// const express = require('express');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const nodemailer = require('nodemailer');
// const crypto = require('crypto');
// const { createUserModel } = require('../../../models/users');
// const router = express.Router();
// const connectDB = require('../../../config/db');
// const sendEmail = require('../auth/mail');
// const rateLimit = require('express-rate-limit');
// let db;

// // Rate limiting for authentication routes
// const authLimiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 15 // limit each IP to 5 requests per windowMs
// });

// // Establish database connection
// connectDB().then(database => {
//     db = database;
// });

// // Input validation middleware
// const validateRegistrationInput = (req, res, next) => {
//     const { name, email, password } = req.body;
    
//     if (!email?.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
//         return res.status(400).json({ error: 'Invalid email format' });
//     }
    
//     if (!password || password.length < 8) {
//         return res.status(400).json({ error: 'Password must be at least 8 characters long' });
//     }
    
//     if (!name || name.length < 2) {
//         return res.status(400).json({ error: 'Name must be at least 2 characters long' });
//     }
    
//     next();
// };

// // Route for registration with email OTP verification
// router.post('/register', authLimiter, validateRegistrationInput, async (req, res) => {
//     const { name, email, password, otp } = req.body;

//     try {
//         const usersCollection = createUserModel(db);

//         // Case-insensitive email check
//         const existingUser = await usersCollection.findOne({ 
//             email: { $regex: new RegExp(`^${email}$`, 'i') } 
//         });
        
//         if (existingUser) {
//             return res.status(400).json({ error: 'User already exists' });
//         }

//         const otpRecord = await db.collection('otps').findOne({ 
//             email,
//             otp,
//             expiry: { $gt: Date.now() }
//         });
        
//         if (!otpRecord) {
//             return res.status(400).json({ error: 'Invalid or expired OTP' });
//         }

//         // Use a higher salt rounds value for better security
//         const hashedPassword = await bcrypt.hash(password, 12);
        
//         const newUser = {
//             name: name.trim(),
//             email: email.toLowerCase(),
//             password: hashedPassword,
//             createdAt: new Date(),
//             lastLogin: new Date(),
//             isVerified: true,
//             loginAttempts: 0,
//             status: 'active'
//         };

//         const result = await usersCollection.insertOne(newUser);
        
//         // Clean up used OTP
//         await db.collection('otps').deleteOne({ email, otp });

//         const token = jwt.sign(
//             { 
//                 userId: result.insertedId,
//                 email: newUser.email
//             },
//             process.env.JWT_SECRET_KEY,
//             { 
//                 expiresIn: '1h',
//                 algorithm: 'HS256'
//             }
//         );

//         res.status(201).json({ 
//             message: 'User registered successfully',
//             token,
//             user: {
//                 id: result.insertedId,
//                 name: newUser.name,
//                 email: newUser.email,
//                 createdAt: newUser.createdAt
//             }
//         });
//     } catch (error) {
//         console.error('Registration error:', error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// // Route to request OTP with rate limiting
// router.post('/request-otp', authLimiter, async (req, res) => {
//     const { email } = req.body;
    
//     if (!email?.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
//         return res.status(400).json({ error: 'Invalid email format' });
//     }

//     try {
//         // Generate a cryptographically secure OTP
//         const otp = crypto.randomInt(100000, 999999).toString();
//         const expiryTime = Date.now() + 10 * 60 * 1000; // 10 minutes

//         // Delete any existing OTPs for this email
//         await db.collection('otps').deleteMany({ email });

//         // Save new OTP
//         await db.collection('otps').insertOne({
//             email: email.toLowerCase(),
//             otp: await bcrypt.hash(otp, 8), // Hash OTP before storing
//             expiry: expiryTime,
//             attempts: 0,
//             createdAt: new Date()
//         });

//         await sendEmail(email, 'Your OTP for Registration', 
//             `Your OTP is ${otp}. It will expire in 10 minutes. Do not share this with anyone.`
//         );

//         res.status(200).json({ 
//             message: 'OTP sent to email',
//             expiresIn: '10 minutes'
//         });
//     } catch (error) {
//         console.error('OTP request error:', error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// // Enhanced login route with security features
// router.post('/login', authLimiter, async (req, res) => {
//     const { email, password } = req.body;

//     try {
//         const usersCollection = createUserModel(db);
//         const user = await usersCollection.findOne({ 
//             email: email.toLowerCase() 
//         });

//         if (!user) {
//             return res.status(400).json({ error: 'Invalid credentials' });
//         }

//         // Check if account is locked
//         if (user.loginAttempts >= 5 && user.lockUntil && user.lockUntil > Date.now()) {
//             return res.status(403).json({ 
//                 error: 'Account temporarily locked. Please try again later.' 
//             });
//         }

//         const isMatch = await bcrypt.compare(password, user.password);
        
//         if (!isMatch) {
//             // Increment login attempts
//             await usersCollection.updateOne(
//                 { _id: user._id },
//                 { 
//                     $inc: { loginAttempts: 1 },
//                     $set: { 
//                         lockUntil: user.loginAttempts >= 4 ? Date.now() + 15 * 60 * 1000 : null 
//                     }
//                 }
//             );
            
//             return res.status(400).json({ error: 'Invalid credentials' });
//         }

//         // Reset login attempts on successful login
//         await usersCollection.updateOne(
//             { _id: user._id },
//             { 
//                 $set: { 
//                     loginAttempts: 0,
//                     lockUntil: null,
//                     lastLogin: new Date()
//                 }
//             }
//         );

//         const token = jwt.sign(
//             { 
//                 userId: user._id,
//                 email: user.email
//             },
//             process.env.JWT_SECRET_KEY,
//             { 
//                 expiresIn: '1h',
//                 algorithm: 'HS256'
//             }
//         );

//         res.json({ 
//             token,
//             user: {
//                 id: user._id,
//                 name: user.name,
//                 email: user.email,
//                 lastLogin: user.lastLogin
//             }
//         });
//     } catch (error) {
//         console.error('Login error:', error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// // Enhanced password reset functionality
// router.post('/reset-password', authLimiter, async (req, res) => {
//     const { email, otp, newPassword } = req.body;

//     if (!newPassword || newPassword.length < 8) {
//         return res.status(400).json({ error: 'New password must be at least 8 characters long' });
//     }

//     try {
//         const otpRecord = await db.collection('otps').findOne({ 
//             email,
//             expiry: { $gt: Date.now() }
//         });

//         if (!otpRecord) {
//             return res.status(400).json({ error: 'Invalid or expired OTP' });
//         }

//         // Verify OTP
//         const isValidOTP = await bcrypt.compare(otp, otpRecord.otp);
//         if (!isValidOTP) {
//             await db.collection('otps').updateOne(
//                 { _id: otpRecord._id },
//                 { $inc: { attempts: 1 } }
//             );
            
//             if (otpRecord.attempts >= 3) {
//                 await db.collection('otps').deleteOne({ _id: otpRecord._id });
//                 return res.status(400).json({ error: 'Too many invalid attempts. Please request a new OTP.' });
//             }
            
//             return res.status(400).json({ error: 'Invalid OTP' });
//         }

//         const hashedPassword = await bcrypt.hash(newPassword, 12);
        
//         await db.collection('users').updateOne(
//             { email: email.toLowerCase() },
//             { 
//                 $set: { 
//                     password: hashedPassword,
//                     passwordChangedAt: new Date(),
//                     loginAttempts: 0,
//                     lockUntil: null
//                 }
//             }
//         );

//         // Clean up used OTP
//         await db.collection('otps').deleteOne({ _id: otpRecord._id });

//         res.status(200).json({ message: 'Password reset successfully' });
//     } catch (error) {
//         console.error('Password reset error:', error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// module.exports = router;


// const express = require('express');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const { createUserModel } = require('../../../models/users'); // Adjust import as needed
// const router = express.Router();
// const connectDB = require('../../../config/db'); // Import the database connection

// let db; // Declare a variable to hold the database connection

// // Establish a connection to the database
// connectDB().then(database => {
//     db = database; // Assign the connected database to the db variable
// });

// // Define a route for user registration
// router.post('/register', async (req, res) => {
//     const { name, email, password } = req.body;

//     try {
//         const usersCollection = createUserModel(db); // Get the users collection

//         // Check if the user already exists
//         const existingUser = await usersCollection.findOne({ email });
//         if (existingUser) {
//             return res.status(400).json({ error: 'User already exists' });
//         }

//         // Hash the password before saving
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Create a new user object
//         const newUser = {
//             name,
//             email,
//             password: hashedPassword,
//             createdAt: new Date(), // Set createdAt to the current date
//         };

//         // Insert the new user into the database
//         await usersCollection.insertOne(newUser);

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
//         const usersCollection = createUserModel(db); // Get the users collection

//         // Find the user by email
//         const user = await usersCollection.findOne({ email });
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
//             email: user.email,
//         };

//         const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

//         res.json({ token });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Server error' });
//     }
// });

// module.exports = router;




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
