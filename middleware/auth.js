const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    // 1. Get the token from the request header
    const authHeader = req.header('Authorization');

    // 2. Check if token exists and is correctly formatted
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token, authorization denied.' });
    }

    try {
        // Extract token from the "Bearer <token>" string
        const token = authHeader.split(' ')[1];

        // 3. Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // 4. Attach the user's information (from the token payload) to the request object
        req.user = decoded; 

        // 5. Pass control to the next function in the stack (the actual route handler)
        next(); 
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid.' });
    }
};

module.exports = auth;

