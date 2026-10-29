
import { createHmac, timingSafeEqual } from "node:crypto";

const getEnv = name => process.env[name];

const json = (data, status = 200) => ({
  statusCode: status,
  headers: {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  },
  body: JSON.stringify(data)
});

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function sign(payload) {
  return createHmac("sha256", getEnv("SESSION_SECRET"))
    .update(payload)
    .digest("base64url");
}

function makeToken() {
  const payload = Buffer.from(JSON.stringify({
    expires: Date.now() + 4 * 60 * 60 * 1000
  })).toString("base64url");

  return payload + "." + sign(payload);
}

function validToken(event) {
  const header = event.headers?.authorization || "";
  const match = header.match(/^Bearer (.+)$/i);
  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  if (!sameSecret(signature, sign(payload))) return false;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );
    return Number(data.expires) > Date.now();
  } catch {
    return false;
  }
}

async function databaseRequest(path, options = {}) {
  const base = getEnv("SUPABASE_URL");
  const key = getEnv("SUPABASE_SECRET_KEY");

  if (!base || !key) throw new Error("Database is not configured.");

  const response = await fetch(
    base.replace(/\/$/, "") + "/rest/v1/" + path,
    {
      ...options,
      headers: {
        "apikey": key,
        "Authorization": "Bearer " + key,
        "Content-Type": "application/json",
        ...options.headers
      }
    }
  );

  if (!response.ok) {
    console.error("Database request failed:", response.status);
    throw new Error("Database request failed.");
  }

  if (response.status === 204) return null;
  return response.json();
}

export default async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json({ error: "Method not allowed." }, 405);
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  try {
    // Public survey submission
    if (body.action === "submit") {
      const love = body.love;
      const username = typeof body.username === "string"
        ? body.username.trim() : "";
      const favorite = typeof body.favorite === "string"
        ? body.favorite.trim() : "";

      if (
        !["Yes! ❤️", "It's okay", "No"].includes(love) ||
        !username || username.length > 50 ||
        !favorite || favorite.length > 100
      ) {
        return json({ error: "Please complete all questions correctly." }, 400);
      }

      await databaseRequest("roblox_responses", {
        method: "POST",
        headers: { "Prefer": "return=minimal" },
        body: JSON.stringify({ love, username, favorite })
      });

      return json({ success: true });
    }

    // Developer login
    if (body.action === "login") {
      if (!sameSecret(body.password, getEnv("DEVELOPER_PASSWORD"))) {
        return json({ error: "Incorrect password." }, 401);
      }

      return json({ token: makeToken() });
    }

    // Private dashboard results
    if (body.action === "results") {
      if (!validToken(event)) {
        return json({ error: "Session expired. Please log in again." }, 401);
      }

      const rows = await databaseRequest(
        "roblox_responses?select=id,love,username,favorite,created_at&order=created_at.desc&limit=500"
      );

      return json({ responses: rows });
    }

    return json({ error: "Unknown request." }, 400);
  } catch (error) {
    console.error(error);
    return json({
      error: "The server could not complete the request. Please try again."
    }, 500);
  }
}
