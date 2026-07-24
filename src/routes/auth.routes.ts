import { crypto } from "node:crypto";
import { Request, Response, Router } from "express";

const router = Router();

// Usiamo il database sicuro della registrazione creato precedentemente
// (In un'app reale questi dati arriverebbero dal Database)
import { secureUsersDb } from "./users.routes";

/* ==========================================================================
   1. LOGIN VULNERABILE ❌
   ========================================================================== */
router.post("/login-vulnerable", (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = secureUsersDb.find((u) => u.email === email);

  // ❌ VULNERABILITÀ 1: User Enumeration
  // Riveliamo all'attaccante che l'email non esiste!
  if (!user) {
    return res.status(404).json({ error: "Utente non trovato nel sistema." });
  }

  // ❌ VULNERABILITÀ 2: Messaggio troppo specifico per password errata
  // L'attaccante ora sa con certezza che l'email esiste e deve solo indovinare la password.
  // Nota: Qui simuliamo il confronto errato in chiaro per scopo dimostrativo.
  if (user.passwordHash !== password) {
    return res.status(401).json({ error: "Password errata per questa email." });
  }

  res.json({
    message: "Login effettuato (Vulnerabile)!",
    user: { id: user.id, email: user.email, role: user.role }
  });
});

/* ==========================================================================
   2. LOGIN SICURO ✅ (Verifica Hash PBKDF2 + Nessuna User Enumeration)
   ========================================================================== */

// Helper per verificare la password usando PBKDF2 e timing sicuro
function verifyPasswordNative(password: string, hash: string, salt: string): Promise<boolean> {
  return new Promise((resolve) => {
    crypto.pbkdf2(password, salt, 100000, 64, "sha512", (err, derivedKey) => {
      if (err) return resolve(false);
      
      const computedHash = derivedKey.toString("hex");
      
      // ✅ Confronto a tempo costante per prevenire Timing Attacks
      const isMatch = crypto.timingSafeEqual(
        Buffer.from(computedHash, "hex"),
        Buffer.from(hash, "hex")
      );
      resolve(isMatch);
    });
  });
}

router.post("/login-secure", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // 1. Validazione di base dell'input
    if (!email || !password || typeof password !== "string") {
      return res.status(400).json({ error: "Credenziali non valide." });
    }

    const user = secureUsersDb.find((u) => u.email === email.toLowerCase().trim());

    // 2. Verifica dell'Hash
    let isValid = false;
    if (user) {
      isValid = await verifyPasswordNative(password, user.passwordHash, user.salt);
    }

    // ✅ SICUREZZA: Messaggio generico per prevenire User Enumeration
    // Sia che l'email non esista, sia che la password sia sbagliata, la risposta è IDENTICA.
    if (!user || !isValid) {
      return res.status(401).json({ error: "Credenziali non valide." });
    }

    // 3. Risposta di successo
    res.json({
      message: "Login effettuato con successo!",
      user: { id: user.id, email: user.email, role: user.role }
    });

  } catch (error) {
    res.status(500).json({ error: "Errore interno del server." });
  }
});

export default router;