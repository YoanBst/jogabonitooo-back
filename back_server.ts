import { Application, Router } from "https://deno.land/x/oak@v11.1.0/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.2.4/mod.ts";
import { Client } from "https://deno.land/x/postgres@v0.17.0/mod.ts"; // PostgreSQL import
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import { setCookie } from "https://deno.land/x/oak@v11.1.0/cookies.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.6/mod.ts";
import { decode } from "https://deno.land/x/djwt/mod.ts";


const client = new Client({
  user: "postgres",
  password: "447573369753b1c9829d29aaf55e14c2",
  database: "jogabonitooo_db",
  hostname: "dokku-postgres-jogabonitooo-db",
  port: 5432,
  tls: false // ou true si Dooku/Postgres l'exige
});
await client.connect();

const app = new Application();

app.use(oakCors({
  origin: "https://jogabonitooo-front.cluster-ig3.igpolytech.fr",
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

const router = new Router();
const connections = new Set<WebSocket>();

// Fonction pour insérer un message dans la base de données
async function insertMessage(owner: string, message: string) {
  try {
    await client.queryObject(
      "INSERT INTO messages (owner, message) VALUES ($1, $2)",
      [owner, message]
    );
    console.log("Message inséré dans la base de données.");
  } catch (error) {
    console.error("Erreur lors de l'insertion du message dans la base de données:", error);
  }
}

app.use(async (ctx, next) => {
  try {
    await next();
  } catch (err) {
    console.error("Erreur HTTP:", err);
    ctx.response.status = 400;
    ctx.response.body = { error: "Méthode HTTP invalide ou mal formée" };
  }
});

// Route pour la commande
router.post("/api/commande", async (ctx) => {
  try {
    const body = await ctx.request.body({ type: "json" });
    const { owner, country, adress, total, basket } = await body.value;

    if (!owner || !country || !adress || !total || !basket || !Array.isArray(basket)) {
      ctx.response.status = 400;
      ctx.response.body = { success: false, message: "Champs manquants ou invalides" };
      return;
    }

    await client.queryArray("BEGIN");

    const commandeResult = await client.queryObject<{ id: number }>(
      "INSERT INTO commandes (owner, adress, total) VALUES ($1, $2, $3) RETURNING id",
      [owner, adress, total]
    );
    const lastCommandeId = commandeResult.rows[0].id;

    await client.queryObject(
      "INSERT INTO delivery_country (commande_id, country) VALUES ($1, $2)",
      [lastCommandeId, country]
    );

    for (const item of basket) {
      await client.queryObject(
        "INSERT INTO command_items (commande_id, product_name, price, quantity, size) VALUES ($1, $2, $3, $4, $5)",
        [lastCommandeId, item.name, item.price, item.quantity, item.size ?? null]
      );
}

    await client.queryArray("COMMIT");

    ctx.response.status = 200;
    ctx.response.body = { success: true, message: "Commande enregistrée avec succès" };
  } catch (error) {
    await client.queryArray("ROLLBACK");
    console.error("Erreur lors de l'enregistrement de la commande :", error);
    ctx.response.status = 500;
    ctx.response.body = { success: false, message: "Erreur serveur", error: error.message };
  }
});



router.get("/api/messages", async (ctx) => {
  try {
    const result = await client.queryObject<{ owner: string; message: string }>(
      "SELECT owner, message FROM messages ORDER BY RANDOM() LIMIT 4"
    );
    ctx.response.status = 200;
    ctx.response.body = { messages: result.rows };
  } catch (error) {
    ctx.response.status = 500;
    ctx.response.body = { error: "Erreur lors de la récupération des messages" };
  }
});


// route pour l'admin
router.get("/users", async (ctx) => {
  try {
    console.log("✅ Route /users hit");
    const result = await client.queryObject<{ id: number; username: string }>(
      "SELECT id, username FROM users WHERE role = 'user'"
    );
    ctx.response.status = 200;
    ctx.response.body = { users: result.rows };
  } catch (error) {
    console.error("🔥 Error in /users:", error.message);
    ctx.response.status = 500;
    ctx.response.body = { message: "Internal Server Error" };
  }
});

router.delete("/users/:id", async (ctx) => {
  try {
    const { id } = ctx.params;
    console.log(`✅ Suppression de l'utilisateur avec l'ID: ${id}`);
    const result = await client.queryObject(
      "DELETE FROM users WHERE id = $1",
      [id]
    );
    // result.rowCount pour vérifier la suppression
    if (result.rowCount === 0) {
      ctx.response.status = 404;
      ctx.response.body = { message: "User not found" };
      return;
    }
    ctx.response.status = 200;
    ctx.response.body = { message: "User deleted" };
  } catch (error) {
    console.error("🔥 Error in /users/:id delete:", error.message);
    ctx.response.status = 500;
    ctx.response.body = { message: "Internal Server Error" };
  }
});

// Fonction pour hasher le mot de passe
async function get_hash(password: string): Promise<string> {
  try {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    console.error("Error hashing password:", error);
    throw error;
  }
}

// Route d'enregistrement
router.post("/register", async (ctx) => {
  console.log("✅ Route /register hit");
  try {
    const body = await ctx.request.body({ type: "json" }).value;
    const { username, password } = body;

    if (!username || !password) {
      ctx.response.status = 400;
      ctx.response.body = { message: "Username and password are required" };
      return;
    }

    console.log("🔐 Checking if username exists:", username);
    const result = await client.queryObject<{ id: number }>(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );
    if (result.rows.length > 0) {
      ctx.response.status = 409;
      ctx.response.body = { message: "Username already exists" };
      return;
    }

    const password_hash = await get_hash(password);
    const role = (username === "admin30190") ? "admin" : "user";

    const insertResult = await client.queryObject<{ id: number }>(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
      [username, password_hash, role]
    );
    const userId = insertResult.rows[0].id;

    ctx.response.status = 201;
    ctx.response.body = { message: "Registration successful!", userId };
  } catch (error) {
    console.error("🔥 Error in /register:", error.message, error.stack);
    ctx.response.status = 500;
    ctx.response.body = { message: "Internal Server Error", error: error.message };
  }
});

// 🔐 Initialisation de la clé secrète pour JWT
const secretString = "vraiment-secret";
const secretKey = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(secretString),
  { name: "HMAC", hash: "SHA-512" },
  false,
  ["sign", "verify"]
);

router.post("/login", async (ctx) => {
  console.log("✅ Route /login hit");
  try {
    const body = await ctx.request.body({ type: "json" }).value;
    const { username, password } = body;

    if (!username || !password) {
      ctx.response.status = 400;
      ctx.response.body = { message: "Username and password are required" };
      console.log("❌ Missing username or password");
      return;
    }

    const result = await client.queryObject<{ id: number; password_hash: string; role: string }>(
      "SELECT id, password_hash, role FROM users WHERE username = $1",
      [username]
    );
    if (result.rows.length === 0) {
      ctx.response.status = 401;
      ctx.response.body = { message: "Invalid username or password" };
      console.log("❌ Invalid username or password");
      return;
    }

    const userId = result.rows[0].id;
    const password_hash = result.rows[0].password_hash;
    const role = result.rows[0].role;

    const match = await bcrypt.compare(password, password_hash);

    if (!match) {
      ctx.response.status = 401;
      ctx.response.body = { message: "Invalid username or password" };
      console.log("❌ Password mismatch");
      return;
    }

    const payload = { username };
    const token = await create({ alg: "HS512", typ: "JWT" }, payload, secretKey);

    ctx.response.headers.set(
      "Set-Cookie",
      `auth_token=${token}; HttpOnly; Secure; SameSite=None; Max-Age=3600`
    );

    ctx.response.status = 200;
    ctx.response.body = { message: "Login successful", userId, role };

    console.log("✅ Login successful");
  } catch (error) {
    console.error("🔥 Error in /login:", error.message);
    ctx.response.status = 500;
    ctx.response.body = {
      message: "Internal Server Error",
      error: error.message,
    };
  }
});

router.get("/get-token", async (ctx) => {
  console.log("✅ Route /get-token hit");
  const token = await ctx.cookies.get("auth_token");
  console.log("Retrieved token from cookies:", token);

  if (!token || typeof token !== "string") {
    ctx.response.status = 404;
    ctx.response.body = { message: "Token not found" };
    console.log("❌ Token not found");
    return;
  }

  ctx.response.status = 200;
  ctx.response.body = { auth_token: token };
  console.log("✅ Token returned to client");
});

// WebSocket handler
router.get("/ws", async (ctx) => {
  if (ctx.isUpgradable) {
    const socket = await ctx.upgrade();
    console.log("✅ WebSocket connection established");

    connections.add(socket);

    socket.onmessage = async (event) => {
      try {
        console.log("WebSocket message received:", event.data);
        const data = JSON.parse(event.data);
        const token = data.auth_token;
        console.log("Extracted token from WebSocket:", token);

        if (!token) {
          socket.send(JSON.stringify({ error: "Unauthorized: No token provided" }));
          console.log("❌ No token in WebSocket message");
          return;
        }

        const payload = await verify(token, secretKey);
        console.log("Token verified for WebSocket, payload:", payload);

        const username = payload.username;

        await insertMessage(username, data.message);
        console.log("Message inserted into DB:", data.message);

        const outgoingMessage = JSON.stringify({
          owner: username,
          message: data.message,
        });

        for (const clientSocket of connections) {
          if (clientSocket.readyState === WebSocket.OPEN) {
            clientSocket.send(outgoingMessage);
          }
        }
        console.log("✅ Message broadcasted to all WebSocket clients");
      } catch (err) {
        console.error("🔥 Error handling WebSocket message:", err);
        socket.send(JSON.stringify({ error: "Unauthorized: Invalid token" }));
      }
    };

    socket.onclose = () => {
      connections.delete(socket);
      console.log("🔌 WebSocket connection closed");
    };
  } else {
    ctx.throw(400, "WebSocket Upgrade required");
  }
});

router.get("/me", async (ctx) => {
  console.log("✅ Route /me hit");

  const token = ctx.cookies.get("auth_token");
  console.log("Received token:", token);

  if (!token) {
    ctx.response.status = 401;
    ctx.response.body = { error: "Unauthorized" };
    console.log("❌ No token found, unauthorized");
    return;
  }

  try {
    const payload = await verify(token, secretKey);
    console.log("Token verified, payload:", payload);

    const result = await client.queryObject<{ username: string; name: string }>(
      "SELECT username, name FROM users WHERE username = $1",
      [payload.username]
    );
    if (result.rows.length === 0) {
      ctx.response.status = 401;
      ctx.response.body = { error: "Unauthorized" };
      console.log("❌ User not found, unauthorized");
      return;
    }

    const user = result.rows[0];
    ctx.response.status = 200;
    ctx.response.body = { username: user.username, name: user.name };
    console.log("✅ User found, user data sent");
  } catch (err) {
    console.error("🔥 Error in /me:", err.message, err.stack);
    ctx.response.status = 401;
    ctx.response.body = { error: "Unauthorized" };
  }
});

async function createDefaultUser() {
  try {
    const result = await client.queryObject<{ id: number }>(
      "SELECT id FROM users WHERE username = $1",
      ["admin30190"]
    );
    if (result.rows.length === 0) {
      const password_hash = await get_hash("bastides");
      const role = "admin";
      await client.queryObject(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
        ["admin30190", password_hash, role]
      );
      console.log("✅ Utilisateur 'admin30190' créé avec succès.");
    } else {
      console.log("✅ L'utilisateur 'admin30190' existe déjà.");
    }
  } catch (error) {
    console.error("🔥 Erreur lors de la création de l'utilisateur par défaut :", error.message);
  }
}
createDefaultUser();

// Utilisation des routes
app.use(router.routes());
app.use(router.allowedMethods());

// Démarrage du serveur
const PORT = Deno.env.get("PORT") || 3000;
console.log(`Backend ready at http://0.0.0.0:${PORT}`);
await app.listen({ port: +PORT });