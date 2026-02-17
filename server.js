require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

// Confirm DB connection
pool
  .connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection error:", err));

// Middleware to check JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Root route
app.get("/", (req, res) => {
  res.send("Universal Loot API is live 🚀");
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Username and password required");
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
      [username, hashedPassword],
    );
    res.json({ message: "User registered", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error registering user");
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (result.rows.length === 0) return res.status(400).send("User not found");

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).send("Invalid password");

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );
    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error logging in");
  }
});

// GET all items (public)
app.get("/items", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM items");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

// POST new item (protected)
app.post("/items", authenticateToken, async (req, res) => {
  const { name, quantity, price } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO items (name, quantity, price) VALUES ($1, $2, $3) RETURNING *",
      [name, quantity, price],
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error inserting item");
  }
});

// PUT update item by ID (protected)
app.put("/items/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, quantity, price } = req.body;
  try {
    const result = await pool.query(
      "UPDATE items SET name=$1, quantity=$2, price=$3 WHERE id=$4 RETURNING *",
      [name, quantity, price, id],
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error updating item");
  }
});

// DELETE item by ID (protected)
app.delete("/items/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM items WHERE id=$1", [id]);
    res.send(`Item ${id} deleted`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error deleting item");
  }
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log(`🚀 Universal Loot running on port ${port}`),
);
