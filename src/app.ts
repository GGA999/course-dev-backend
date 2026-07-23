import cors from "cors";
import express from "express";
import helmet from "helmet";

// Importa le tue rotte
import usersRouter from "./routes/users.routes.js";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.use("/api/users", usersRouter);

export default app;