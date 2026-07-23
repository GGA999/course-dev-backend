import { crypto } from "node:crypto";
import { Request, Response, Router } from "express";

const router = Router();

// 1. Definiamo un tipo per i nostri utenti invece di 'any'
export interface User {
  id: number;
  email: string;
  passwordHash: string;
  salt: string;
  role: string;
}

// Database simulati in memoria
export const vulnerableUsersDb: any[] = [];
export const secureUsersDb: User[] = [];

/* ==========================================================================
   ROTTE BASE
   ========================================================================== */

router.get("/", (_req: Request, res: Response) => {
  res.json([{ id: 1, name: "Mario Rossi" }]);
});

router.post("/", (req: Request, res: Response) => {
  const newUser = req.body;
  res.status(201).json({ message: "Utente creato", data: newUser });
});

/* ==========================================================================
   1. VERSIONE VULNERABILE ❌
   ========================================================================== */

router.post("/register-vulnerable", (req: Request, res: Response) => {
  const { email, password, role } = req.body;

  const newUser = {
    id: vulnerableUsersDb.length + 1,
    email: email,
    password: password, // ❌ ERRORE GRAVE: Password in chiaro!
    role: role || "user" // ❌ ERRORE GRAVE: Mass Assignment (privilege escalation)
  };

  vulnerableUsersDb.push(newUser);
  res.json({ message: "Utente registrato (Vulnerabile)!", user: newUser });
});

/* ==========================================================================
   2. VERSIONE SICURA (SENZA LIBRERIE ESTERNE - Usando node:crypto) ✅
   ========================================================================== */

// Funzione helper per l'hashing usando il modulo nativo node:crypto
function hashPasswordNative(password: string): Promise<{ hash: string; salt: string }> {
  return new Promise((resolve, reject) => {
    // Generiamo un SALT casuale e unico per ogni utente
    const salt = crypto.randomBytes(16).toString("hex");

    // Deriviamo la chiave tramite algoritmo PBKDF2
    crypto.pbkdf2(password, salt, 100000, 64, "sha512", (err, derivedKey) => {
      if (err) return reject(err);
      resolve({
        hash: derivedKey.toString("hex"),
        salt: salt
      });
    });
  });
}

router.post("/register-secure", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // 1. Validazione Tipi e Campi Obbligatori
    if (!email || !password || typeof password !== "string" || typeof email !== "string") {
      return res.status(400).json({ error: "Email e password non valide." });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "La password deve contenere almeno 8 caratteri." });
    }

    // 2. Controllo duplicati
    const existingUser = secureUsersDb.find((u) => u.email === email.toLowerCase().trim());
    if (existingUser) {
      return res.status(409).json({ error: "Utente già registrato." });
    }

    // 3. Hashing Nativo Node.js (PBKDF2 + Salt)
    const { hash, salt } = await hashPasswordNative(password);

    // 4. Sanitizzazione e Dati Sicuri
    const newUser: User = {
      id: secureUsersDb.length + 1,
      email: email.toLowerCase().trim(),
      passwordHash: hash, // ✅ Mai salvare la password originale
      salt: salt,         // ✅ Il salt serve per la successiva verifica in fase di Login
      role: "user"        // ✅ Ruolo hardcodato lato server (Nessun Mass Assignment)
    };

    secureUsersDb.push(newUser);

    // 5. Risposta Sicura (Nascondiamo Hash e Salt dal JSON di ritorno)
    res.status(201).json({
      message: "Utente registrato in modo sicuro!",
      user: { id: newUser.id, email: newUser.email, role: newUser.role }
    });

  } catch (error) {
    res.status(500).json({ error: "Errore interno del server." });
  }
});

export default router;