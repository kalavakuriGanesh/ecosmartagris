const jwt = require('jsonwebtoken');

const retailerAuth = async (req, res, next) => {
    try {
        const token = req.cookies.json;
        if (!token) {
            return res.redirect('/login');
        }

        const decoded = jwt.verify(token, process.env.BYTPASS);
        if (decoded.role !== 'customer') {
            return res.status(403).send('Access denied. Only retailers can perform this action.');
        }

        req.user = decoded;
        res.locals.user = decoded;
        next();
    } catch (error) {
        res.redirect('/login');
    }
};

module.exports = retailerAuth; 