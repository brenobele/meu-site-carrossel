const express = require("express");
const multer = require("multer");
const path = require("node:path");
const fs = require("node:fs");
const session = require("express-session");
const sharp = require("sharp");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

const ADMIN_USER = "admin";
const ADMIN_PASS = process.env.ADMIN_PASS;
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

app.set(helmet());
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: IS_PRODUCTION, maxAge: 60000 * 60 * 24 },
  })
);

// Configuração do Multer (Upload de Imagens)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage: storage,
  // [VALIDAÇÃO 1] Tamanho: 5MB (em bytes: 5 * 1024 * 1024)
  limits: { fileSize: 5 * 1024 * 1024 },

  // [VALIDAÇÃO 2] Tipo de Arquivo: Apenas JPG e PNG
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
  const directoryPath = path.join(__dirname, "public/uploads");
  fs.readdir(directoryPath, (err, files) => {
    if (err) return res.render("index", { images: [] });
    const images = files.filter((file) => /\.(jpg|jpeg|png|)$/i.test(file));
    res.render("index", { images: images });
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

  if (usuario === ADMIN_USER && senha === ADMIN_PASS) {
    req.session.loggedin = true;
    req.session.username = usuario;
    res.redirect("/admin");
  } else {
    req.session.error = "Usuário ou senha incorretos!";
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.cookie("connect.sid", { maxAge: 0 });
  res.redirect("/");
});

app.get("/admin", checkAuth, (req, res) => {
  const directoryPath = path.join(__dirname, "public/uploads");

  const errorMessage = req.session.error;
  const successMessage = req.session.success;

  req.session.error = null;
  req.session.success = null;

  fs.readdir(directoryPath, (err, files) => {
    const images = err
      ? []
      : files.filter((file) => /\.(jpg|jpeg|png|gif)$/i.test(file));

    res.render("admin", {
      images: images,
      error: errorMessage,
      success: successMessage,
    });
  });
});

app.post("/delete", checkAuth, (req, res) => {
  const imageName = req.body.imageName;

  const safeName = path.basename(imageName);
  const imagePath = path.join(__dirname, "public/uploads", safeName);

  fs.unlink(imagePath, (err) => {
    if (err) {
      console.error("Erro ao deletar:", err);
    }
    res.redirect("/admin");
  });
});

app.post("/upload", checkAuth, (req, res) => {
  const uploadSingle = upload.single("image");

  uploadSingle(req, res, async (err) => {
    const setErrorAndRedirect = (msg) => {
      req.session.error = msg;
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
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
      const metadata = await sharp(req.file.path).metadata();
      const MAX_DIMENSION = 2560; // Limite 2K

      if (metadata.width > MAX_DIMENSION || metadata.height > MAX_DIMENSION) {
        return setErrorAndRedirect(
          `Resolução muito alta (${metadata.width}x${metadata.height}px). O máximo permitido é 2560px.`
        );
      }

      req.session.success = "Imagem enviada com sucesso!";
      res.redirect("/admin");
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
