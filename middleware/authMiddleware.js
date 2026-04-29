const jwt = require("jsonwebtoken");
const db = require("../db/database");

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token || req.headers["authorization"]?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "No token provided" });
    }

    const blacklisted = db
        .prepare("SELECT * FROM token_blacklist WHERE token = ?")
        .get(token);

    if (blacklisted) {
        return res.status(401).json({ error: "Token invalidated" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
};

module.exports = authMiddleware;