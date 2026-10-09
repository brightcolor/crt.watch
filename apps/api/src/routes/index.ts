import { Router } from "express";
import { requireAuth, resolveTenant } from "../auth/auth.js";
import { csrfProtection } from "../security/csrf.js";
import { authRoutes } from "./authRoutes.js";
import { monitorRoutes } from "./monitorRoutes.js";
import { systemRoutes } from "./systemRoutes.js";
import { exportRoutes } from "./exportRoutes.js";
import { opsRoutes } from "./opsRoutes.js";
import { forwardRejections } from "./errors.js";

export const apiRoutes = Router();

// First, so that every changing request of the API passes it, sign-in and setup included.
apiRoutes.use(csrfProtection);
apiRoutes.use("/auth", authRoutes);
apiRoutes.get("/health", (_req, res) => res.json({ ok: true }));
apiRoutes.use(requireAuth);
apiRoutes.use(resolveTenant);
apiRoutes.use("/monitors", monitorRoutes);
apiRoutes.use("/", opsRoutes);
apiRoutes.use("/", systemRoutes);
apiRoutes.use("/export", exportRoutes);

// Last, when every route below /api exists: a rejected promise of any handler reaches the error middleware.
forwardRejections(apiRoutes);
