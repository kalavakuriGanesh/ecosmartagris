const jwt = require('jsonwebtoken');

const auth = async (req, res, next) => {
    try {
        const token = req.cookies.json;
        if (!token) {
            return res.redirect('/login');
        }

        const decoded = jwt.verify(token, process.env.BYTPASS);
        req.user = decoded;
        res.locals.user = decoded;
        next();
    } catch (error) {
        res.redirect('/login');
    }
};

module.exports = auth; 