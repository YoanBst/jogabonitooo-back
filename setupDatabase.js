const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'base',
  port: 5432,
  password: '123',
});


async function createTables() {
  try {
    // Table users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
      );
    `);

    // Table commandes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS commandes (
        id SERIAL PRIMARY KEY,
        owner TEXT NOT NULL,
        adress TEXT NOT NULL,
        total REAL NOT NULL
      );
    `);

    // Table delivery_country
    await pool.query(`
      CREATE TABLE IF NOT EXISTS delivery_country (
        id SERIAL PRIMARY KEY,
        commande_id INTEGER NOT NULL REFERENCES commandes(id),
        country TEXT NOT NULL
      );
    `);

    // Table command_items
    await pool.query(`
      CREATE TABLE IF NOT EXISTS command_items (
        id SERIAL PRIMARY KEY,
        commande_id INTEGER NOT NULL REFERENCES commandes(id),
        product_name TEXT NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        size TEXT
        
      );
    `);

    // Table messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        owner TEXT NOT NULL,
        message TEXT NOT NULL
      );
    `);

    console.log("Toutes les tables ont été créées avec succès !");
  } catch (err) {
    console.error("Erreur lors de la création des tables :", err);
  } finally {
    await pool.end();
  }
}

createTables();
