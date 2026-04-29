const express = require("express");
const router = express.Router();
const db = require("../db/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const authMiddleware = require("../middleware/authMiddleware");

router.post("/register", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Invalid credentials" });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    if (!/[A-Z]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one uppercase letter" });
    }

    if (!/[0-9]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one number" });
    }

    const password_hash = bcrypt.hashSync(password, 12);

    try {
        const stmt = db.prepare(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)"
        );
        stmt.run(email, password_hash);
        return res.status(201).json({ message: "User created" });
    } catch (err) {
        return res.status(400).json({ error: "Invalid credentials" });
    }
});

router.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    if (user.locked) {
        return res.status(403).json({ error: "Account locked. Try again later." });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);

    if (!valid) {
        const attempts = user.failed_attempts + 1;

        if (attempts >= 3) {
            db.prepare("UPDATE users SET failed_attempts = ?, locked = 1 WHERE id = ?")
                .run(attempts, user.id);
            return res.status(403).json({ error: "Account locked after too many failed attempts." });
        }

        db.prepare("UPDATE users SET failed_attempts = ? WHERE id = ?")
            .run(attempts, user.id);

        return res.status(401).json({ error: "Invalid credentials" });
    }

    db.prepare("UPDATE users SET failed_attempts = 0, locked = 0 WHERE id = ?")
        .run(user.id);

    const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.cookie("token", token, {
        httpOnly: true,
        secure: false, // pt HTTP
        sameSite: "Strict",
        maxAge: 60 * 60 * 1000
    });

    return res.status(200).json({ message: "Login successful" });
});

router.post("/logout", (req, res) => {
    const token = req.cookies.token;
    
    if (token) {
        db.prepare("INSERT INTO token_blacklist (token) VALUES (?)").run(token);
    }
    
    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out" });
});

router.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user) {
        return res.status(200).json({ message: "If this email exists, a reset token was sent." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires_at = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare(
        "INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)"
    ).run(email, token, expires_at);

    return res.status(200).json({ message: "If this email exists, a reset token was sent.", token });
});

router.post("/reset-password", (req, res) => {
    const { token, new_password } = req.body;

    const record = db
        .prepare("SELECT * FROM reset_tokens WHERE token = ? AND used = 0")
        .get(token);

    if (!record) {
        return res.status(400).json({ error: "Invalid or expired token" });
    }

    if (new Date() > new Date(record.expires_at)) {
        return res.status(400).json({ error: "Invalid or expired token" });
    }

    if (!new_password || new_password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const password_hash = bcrypt.hashSync(new_password, 12);

    db.prepare("UPDATE users SET password_hash = ? WHERE email = ?").run(
        password_hash,
        record.email
    );

    db.prepare("UPDATE reset_tokens SET used = 1 WHERE token = ?").run(token);

    return res.status(200).json({ message: "Password reset successful" });
});

router.get("/me", authMiddleware, (req, res) => {
    const user = db
        .prepare("SELECT id, email, role, created_at FROM users WHERE id = ?")
        .get(req.user.id);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json(user);
});

module.exports = router;