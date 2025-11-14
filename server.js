const express = require("express");
const multer = require("multer");
const path = require("node:path");
const fs = require("node:fs");
const session = require("express-session");
const sharp = require("sharp");
const helmet = require("helmet");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("node:crypto");
const bcrypt = require("bcrypt");

require("dotenv").config();

const app = express();

const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const db = new sqlite3.Database(
  "./database.db",
  sqlite3.OPEN_READWRITE,
  (err) => {
    if (err) {
      console.error("Erro ao conectar no banco de dados:", err.message);
    } else {
      console.log("Conectado ao banco de dados SQLite.");
    }
  }
);

app.use(helmet());
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: IS_PRODUCTION,
      maxAge: 60000 * 60 * 24,
      sameSite: "lax",
    },
  })
);

// Configuração do Multer (Upload de Imagens)
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/png", "image/jpg"];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Formato inválido! Apenas JPG e PNG são permitidos."));
    }
  },
});

// --- MIDDLEWARE DE PROTEÇÃO ---
function checkAuth(req, res, next) {
  if (req.session?.loggedin) {
    return next();
  } else {
    res.redirect("/login");
  }
}

app.get("/", (req, res) => {
  const sql = "SELECT id FROM imagens ORDER BY data_upload DESC";

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Erro ao buscar imagens:", err);
      return res.render("index", { images: [] });
    }
    // 'rows' será: [{id: 1}, {id: 2}, {id: 3}]
    res.render("index", { images: rows });
  });
});

app.get("/imagem/:id", (req, res) => {
  const id = Number(req.params.id);
  const sql = "SELECT mimetype, imagem_data FROM imagens WHERE id = ?";

  db.get(sql, [id], (err, row) => {
    if (err || !row) {
      return res.status(404).send("Imagem não encontrada.");
    }

    // Define o cabeçalho de tipo de conteúdo (ex: 'image/jpeg')
    res.setHeader("Content-Type", row.mimetype);
    // Envia o buffer binário (BLOB) como resposta
    res.send(row.imagem_data);
  });
});

app.get("/login", (req, res) => {
  if (req.session.loggedin) return res.redirect("/admin");

  const errorMessage = req.session.error;
  req.session.error = null;

  res.render("login", { error: errorMessage });
});

app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  const sql = "SELECT * FROM usuarios WHERE email = ?";

  db.get(sql, [usuario], (err, user) => {
    if (err) {
      req.session.error = "Erro interno no servidor.";
      return res.redirect("/login");
    }

    if (!user) {
      req.session.error = "Usuário ou senha incorretos!";
      return res.redirect("/login");
    }

    bcrypt.compare(senha, user.senha, (err, isMatch) => {
      if (err) {
        req.session.error = "Erro interno no servidor.";
        return res.redirect("/login");
      }

      if (isMatch) {
        req.session.loggedin = true;
        req.session.username = user.email;
        res.redirect("/admin");
      } else {
        req.session.error = "Usuário ou senha incorretos!";
        res.redirect("/login");
      }
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.cookie("connect.sid", { maxAge: 0 });
  res.redirect("/");
});

app.get("/admin", checkAuth, (req, res) => {
  const errorMessage = req.session.error;
  const successMessage = req.session.success;

  req.session.error = null;
  req.session.success = null;

  const csrfToken = crypto.randomBytes(32).toString("hex");
  req.session.csrfToken = csrfToken;

  const sql = "SELECT id, nome_original FROM imagens ORDER BY data_upload DESC";

  db.all(sql, [], (err, rows) => {
    // 'rows' será: [{id: 1, nome_original: 'foto.jpg'}, ...]
    res.render("admin", {
      images: rows || [],
      error: errorMessage,
      success: successMessage,
      csrfToken: csrfToken,
    });
  });
});

app.post("/delete", checkAuth, (req, res) => {
  const submittedToken = req.body._csrf;
  const sessionToken = req.session.csrfToken;

  req.session.csrfToken = null;

  if (!submittedToken || !sessionToken || submittedToken !== sessionToken) {
    console.warn("Possível ataque CSRF bloqueado.");
    req.session.error = "Ação inválida ou expirada. Tente novamente.";
    return res.redirect("/admin");
  }

  const imageId = Number(req.body.imageId);

  const sql = "DELETE FROM imagens WHERE id = ?";
  db.run(sql, [imageId], (dbErr) => {
    if (dbErr) {
      console.error("Erro ao deletar do banco:", dbErr);
      req.session.error = "Erro ao deletar imagem do banco de dados.";
    } else {
      req.session.success = "Imagem deletada com sucesso.";
    }

    res.redirect("/admin");
  });
});

app.post("/upload", checkAuth, (req, res) => {
  const uploadSingle = upload.single("image");

  uploadSingle(req, res, async (err) => {
    const submittedToken = req.body._csrf;
    const sessionToken = req.session.csrfToken;

    req.session.csrfToken = null;

    if (!submittedToken || !sessionToken || submittedToken !== sessionToken) {
      req.session.error = "Ação inválida ou expirada.";
      return res.redirect("/admin");
    }
    const setErrorAndRedirect = (msg) => {
      req.session.error = msg;
      return res.redirect("/admin");
    };

    if (err instanceof multer.MulterError) {
      return setErrorAndRedirect("O arquivo é muito grande! O limite é 5MB.");
    } else if (err) {
      return setErrorAndRedirect(err.message);
    }

    if (!req.file) {
      return setErrorAndRedirect(
        "Por favor, selecione uma imagem para enviar."
      );
    }

    try {
      const metadata = await sharp(req.file.buffer).metadata();
      const MAX_DIMENSION = 2560;

      if (metadata.width > MAX_DIMENSION || metadata.height > MAX_DIMENSION) {
        return setErrorAndRedirect(
          `Resolução muito alta (${metadata.width}x${metadata.height}px). O máximo permitido é 2560px.`
        );
      }

      const sql =
        "INSERT INTO imagens (nome_original, mimetype, imagem_data, data_upload) VALUES (?, ?, ?, ?)";
      const dataUpload = new Date().toISOString();
      const params = [
        req.file.originalname,
        req.file.mimetype,
        req.file.buffer,
        dataUpload,
      ];

      db.run(sql, params, (dbErr) => {
        if (dbErr) {
          console.error("Erro ao salvar no banco:", dbErr);
          return setErrorAndRedirect("Erro interno ao salvar a imagem.");
        }

        req.session.success = "Imagem enviada com sucesso!";
        res.redirect("/admin");
      });
    } catch (error) {
      console.error(error);
      setErrorAndRedirect("Erro interno ao processar a imagem.");
    }
  });
});

app.use((req, res, next) => {
  res.status(404).render("404");
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("500");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando em http://localhost:" + PORT);
});
