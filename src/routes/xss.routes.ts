import { Request, Response, Router } from "express";

const router = Router();


// [ Attaccante ] --(1. Invia Script)--> [ Backend / DB ] --(2. Salva Grezzo)
//                                                                  |
// [ Vittima ] <--(3. Esegue Script)--- [ Browser ] <--(Legge Data)--+


// Database in memoria per i commenti/post
export const postsDb: { id: number; username: string; content: string }[] = [];

// Funzione di sanitizzazione per la versione sicura
function sanitizeHTML(str: string): string {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ==========================================================================
   1. ENDPOINT VULNERABILE (Salva l'input così com'è)
   ========================================================================== */
router.post("/posts-vulnerable", (req: Request, res: Response) => {
  const { username, content } = req.body;

  const newPost = {
    id: postsDb.length + 1,
    username: username || "Anonimo",
    content: content, // ❌ VULNERABILITÀ: Memorizzazione diretta dell'input non controllato
  };

  postsDb.push(newPost);
  res.status(201).json(newPost);
});

/* ==========================================================================
   2. ENDPOINT SICURO (Sanitizza i caratteri HTML)
   ========================================================================== */
router.post("/posts-secure", (req: Request, res: Response) => {
  const { username, content } = req.body;

  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "Contenuto non valido." });
  }

  const newPost = {
    id: postsDb.length + 1,
    username: sanitizeHTML(username || "Anonimo"),
    content: sanitizeHTML(content),
  };

  postsDb.push(newPost);
  res.status(201).json(newPost);
});

/* ==========================================================================
   3. LETTURA DEI POST
   ========================================================================== */
router.get("/posts", (_req: Request, res: Response) => {
  res.json(postsDb);
});

export default router;