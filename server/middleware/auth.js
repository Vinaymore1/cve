const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const secretKey = process.env.JWT_SECRET_KEY;

    // Check if the Authorization header is present
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, secretKey);
        // Attach the decoded user information to the request object
        req.userId = decoded.userId;

        // Call the next middleware or route handler
        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
};

module.exports = authMiddleware;




// //server/middleware/auth.js
// const jwt = require('jsonwebtoken');

// const authMiddleware = (req, res, next) => {
//     const secretKey = process.env.JWT_SECRET_KEY;
//     const tokenHeaderKey = process.env.JWT_TOKEN_HEADER_KEY;
    
//     try {
//         const token = req.headers[tokenHeaderKey];

//         // Verify the token
//         const decoded = jwt.verify(token, secretKey);
//         // Return the decoded token as the API response
//         // Attach the decoded user information to the request object
//         req.userId = decoded.userId;

//         // Call the next middleware or route handler
//         next();
//     } catch (error) {
//         return res.status(401).json({ message: 'unauthorized' });
//     }
// };

// module.exports = authMiddleware;