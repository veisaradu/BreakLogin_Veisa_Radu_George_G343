const express = require("express");
const router = express.Router();
const db = require("../db/database");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

router.post("/register", (req, res) => {
    const { email, password } = req.body;

    const password_hash = crypto
        .createHash("md5")
        .update(password)
        .digest("hex");

    try {
        const stmt = db.prepare(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)"
        );
        stmt.run(email, password_hash);
        return res.status(201).json({ message: "User created" });
    } catch (err) {
        return res.status(400).json({ error: "Email already exists" });
    }
});

router.post("/login", (req, res) => {
    const { email, password } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user) {
        return res.status(401).json({ error: "User not found" });
    }

    const password_hash = crypto
        .createHash("md5")
        .update(password)
        .digest("hex");

    if (user.password_hash !== password_hash) {
        return res.status(401).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "30d" }
    );

    res.cookie("token", token);
    return res.status(200).json({ message: "Login successful", token });
});

router.post("/logout", (req, res) => {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out" });
});

router.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user) {
        return res.status(404).json({ error: "Email not found" });
    }

    const token = Date.now().toString();
    const expires_at = new Date(Date.now() + 999999999).toISOString();

    db.prepare(
        "INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)"
    ).run(email, token, expires_at);

    return res.status(200).json({ message: "Reset token generated", token });
});

router.post("/reset-password", (req, res) => {
    const { token, new_password } = req.body;

    const record = db
        .prepare("SELECT * FROM reset_tokens WHERE token = ?")
        .get(token);

    if (!record) {
        return res.status(400).json({ error: "Invalid token" });
    }

    const password_hash = crypto
        .createHash("md5")
        .update(new_password)
        .digest("hex");

    db.prepare("UPDATE users SET password_hash = ? WHERE email = ?").run(
        password_hash,
        record.email
    );

    return res.status(200).json({ message: "Password reset successful" });
});

const authMiddleware = require("../middleware/authMiddleware");

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