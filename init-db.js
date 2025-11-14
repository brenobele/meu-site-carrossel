const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
require("dotenv").config();

const ADMIN_EMAIL = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const SALT_ROUNDS = 10;

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    return console.error("Erro ao abrir o banco:", err.message);
  }
  console.log("Conectado ao banco de dados SQLite.");
});

db.serialize(() => {
  db.run(
    `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL
    )
  `,
    (err) => {
      if (err)
        return console.error("Erro ao criar tabela 'usuarios':", err.message);
      console.log("Tabela 'usuarios' verificada/criada.");

      if (ADMIN_EMAIL && ADMIN_PASS) {
        bcrypt.hash(ADMIN_PASS, SALT_ROUNDS, (err, hash) => {
          if (err) return console.error("Erro ao hashear senha:", err);
          const insertSQL = `INSERT OR IGNORE INTO usuarios (email, senha) VALUES (?, ?)`;
          db.run(insertSQL, [ADMIN_EMAIL, hash], function (err) {
            if (err)
              return console.error("Erro ao inserir admin:", err.message);
            if (this.changes > 0) {
              console.log(`Usuário admin (${ADMIN_EMAIL}) criado com sucesso.`);
            } else {
              console.log(`Usuário admin (${ADMIN_EMAIL}) já existia.`);
            }
            closeDB();
          });
        });
      } else {
        console.log(
          "Variáveis ADMIN_USER ou ADMIN_PASS não definidas. Admin não criado."
        );
        closeDB();
      }
    }
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS imagens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome_original TEXT,
      mimetype TEXT NOT NULL,
      imagem_data BLOB NOT NULL, 
      data_upload DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,
    (err) => {
      if (err)
        return console.error("Erro ao criar tabela 'imagens':", err.message);
      console.log("Tabela 'imagens' verificada/criada.");
    }
  );
});

function closeDB() {
  db.close((err) => {
    if (err) return console.error(err.message);
    console.log("Conexão com o banco fechada.");
  });
}
