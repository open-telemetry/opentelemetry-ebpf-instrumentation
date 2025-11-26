// Example Express.js application with various route patterns
const express = require("express");
const app = express();
const router = express.Router();

// Basic routes
app.get("/", (req, res) => {
  res.send("Home");
});

app.post("/users", (req, res) => {
  res.json({ created: true });
});

// Routes with parameters
app.get("/users/:id", (req, res) => {
  res.json({ userId: req.params.id });
});

app.put("/users/:userId/posts/:postId", (req, res) => {
  res.json({ updated: true });
});

// Multiple path segments
app.delete("/api/v1/items/:id", (req, res) => {
  res.status(204).send();
});

// Route chaining
app
  .route("/books")
  .get((req, res) => res.send("Get books"))
  .post((req, res) => res.send("Create book"))
  .put((req, res) => res.send("Update book"));

app
  .route("/books/:id")
  .get((req, res) => res.send("Get book"))
  .delete((req, res) => res.send("Delete book"));

// Router-based routes
router.get("/profile", (req, res) => {
  res.send("User profile");
});

router.post("/settings", (req, res) => {
  res.json({ saved: true });
});

router.patch("/account/:accountId", (req, res) => {
  res.json({ patched: true });
});

// Middleware mount
app.use("/api", router);

// Wildcard routes
app.all("/admin/*", (req, res) => {
  res.send("Admin area");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
