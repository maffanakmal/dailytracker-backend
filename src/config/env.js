// OK, when Module in .env

import dotenv from "dotenv";

dotenv.config();

if (!process.env.SUPABASE_URL) {
  throw new Error("SUPABASE_URL is missing");
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing");
}
