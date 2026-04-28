const express = require("express");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const authRoutes = require("./routes/auth");

const app = express();
const ticketRoutes = require("./routes/tickets");

app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

app.use("/auth", authRoutes);
app.use("/tickets", ticketRoutes);

app.get("/", (req, res) => {
    res.json({ message: "AuthX API is up" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});