const express = require("express");
const router = express.Router();
const db = require("../db/database");
const authMiddleware = require("../middleware/authMiddleware");

router.get("/", authMiddleware, (req, res) => {
    const tickets = db
        .prepare("SELECT * FROM tickets WHERE owner_id = ?")
        .all(req.user.id);
    return res.status(200).json(tickets);
});

router.post("/", authMiddleware, (req, res) => {
    const { title, description, severity } = req.body;

    if (!title) {
        return res.status(400).json({ error: "Title is required" });
    }

    const stmt = db.prepare(
        "INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)"
    );
    const result = stmt.run(
        title,
        description || "",
        severity || "LOW",
        req.user.id
    );

    return res.status(201).json({ 
        message: "Ticket created", 
        id: result.lastInsertRowid 
    });
});

router.get("/:id", authMiddleware, (req, res) => {
    const ticket = db
        .prepare("SELECT * FROM tickets WHERE id = ?")
        .get(req.params.id);

    if (!ticket) {
        return res.status(404).json({ error: "Ticket not found" });
    }

    return res.status(200).json(ticket);
});

module.exports = router;