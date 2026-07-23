import { Router } from "express";

const router = Router();

// GET /api/users
router.get("/", (req, res) => {
  res.json([{ id: 1, name: "Mario Rossi" }]);
});

// POST /api/users
router.post("/", (req, res) => {
  const newUser = req.body;
  res.status(201).json({ message: "Utente creato", data: newUser });
});

export default router;