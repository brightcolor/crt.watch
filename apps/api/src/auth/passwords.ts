import { z } from "zod";
import { env } from "../config/env.js";

/** The password rule for every account: setup, registration, user management and password changes. */
export const passwordRule = (minLength = env.passwordMinLength) =>
  z.string().min(minLength, `Password must be at least ${minLength} characters long.`);
