const express = require("express");
const multer = require("multer");
const path = require("node:path");
const fs = require("node:fs");
const session = require("express-session");
const sharp = require("sharp");
require('dotenv').config();

const app = express();

const ADMIN_USER = "admin";
const ADMIN_PASS = process.env.ADMIN_PASS;

// Configuração do EJS (View Engine)
app.set("view engine", "ejs");

// Necessário para ler dados do formulário de login (req.body)
app.use(express.urlencoded({ extended: true }));

// Pasta pública para arquivos estáticos (CSS, Imagens)
app.use(express.static("public"));

// Configuração da Sessão
app.use(
  session({
    secret: "segredo-super-secreto", // Chave para assinar a sessão
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Em produção (HTTPS), mude para true
  })
);

// Configuração do Multer (Upload de Imagens)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/"); // Salva na pasta public/uploads
  },
  filename: (req, file, cb) => {
    // Salva com timestamp para evitar nomes duplicados
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
// Essa função verifica se o usuário está logado antes de deixar ele ver a página
function checkAuth(req, res, next) {
  if (req.session?.loggedin) {
    return next();
  } else {
    res.redirect("/login");
  }
}

// --- ROTAS ---

// Rota Principal (Pública)
app.get("/", (req, res) => {
  const directoryPath = path.join(__dirname, "public/uploads");
  fs.readdir(directoryPath, (err, files) => {
    if (err) return res.render("index", { images: [] });
    const images = files.filter((file) =>
      /\.(jpg|jpeg|png|gif|webp)$/i.test(file)
    );
    res.render("index", { images: images });
  });
});

// [NOVO] Rotas de Login
app.get("/login", (req, res) => {
  // Se já estiver logado, manda direto pro admin
  if (req.session.loggedin) return res.redirect("/admin");
  res.render("login");
});

app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  // Verifica se usuário e senha batem com as constantes lá de cima
  if (usuario === ADMIN_USER && senha === ADMIN_PASS) {
    req.session.loggedin = true;
    req.session.username = usuario;
    res.redirect("/admin");
  } else {
    // Renderiza a página de login de novo com erro
    res.render("login", { erro: "Usuário ou senha incorretos!" });
  }
});

// [NOVO] Rota de Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Rota do Admin (AGORA PROTEGIDA)
// Adicionei o 'checkAuth' aqui. Ninguém acessa sem estar logado.
app.get("/admin", checkAuth, (req, res) => {
  const directoryPath = path.join(__dirname, "public/uploads");

  // [NOVO] Captura mensagem de erro ou sucesso da sessão
  const errorMessage = req.session.error;
  const successMessage = req.session.success;

  // [NOVO] Limpa as mensagens da sessão para não aparecerem de novo ao recarregar
  req.session.error = null;
  req.session.success = null;

  fs.readdir(directoryPath, (err, files) => {
    const images = err
      ? []
      : files.filter((file) => /\.(jpg|jpeg|png|gif)$/i.test(file));

    // Renderiza enviando as mensagens junto
    res.render("admin", {
      images: images,
      error: errorMessage, // Envia erro (se houver)
      success: successMessage, // Envia sucesso (se houver)
    });
  });
});

// Rota para Excluir Imagem
app.post("/delete", checkAuth, (req, res) => {
  const imageName = req.body.imageName;

  // Segurança básica: garante que só pegue o nome do arquivo, sem caminhos (../)
  const safeName = path.basename(imageName);
  const imagePath = path.join(__dirname, "public/uploads", safeName);

  // Função do Node.js para deletar arquivos (unlink)
  fs.unlink(imagePath, (err) => {
    if (err) {
      console.error("Erro ao deletar:", err);
      // Você poderia mandar uma mensagem de erro aqui se quisesse
    }
    // Redireciona de volta para o admin
    res.redirect("/admin");
  });
});

// --- ROTA DE UPLOAD COM VALIDAÇÃO DE MEDIDAS ---
// Nota: Usamos um 'wrapper' para capturar erros do Multer (tamanho e tipo)
app.post("/upload", checkAuth, (req, res) => {
  const uploadSingle = upload.single("image");

  uploadSingle(req, res, async (err) => {
    // Função auxiliar para definir erro e redirecionar
    const setErrorAndRedirect = (msg) => {
      req.session.error = msg;
      // Se o arquivo foi salvo mas deu erro (ex: resolução), apaga ele
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.redirect("/admin");
    };

    // 1. Erros do Multer (Tamanho ou Tipo)
    if (err instanceof multer.MulterError) {
      return setErrorAndRedirect("O arquivo é muito grande! O limite é 5MB.");
    } else if (err) {
      return setErrorAndRedirect(err.message);
    }

    // 2. Erro: Nenhuma imagem enviada
    if (!req.file) {
      return setErrorAndRedirect(
        "Por favor, selecione uma imagem para enviar."
      );
    }

    // 3. Validação de Resolução (Sharp)
    try {
      const metadata = await sharp(req.file.path).metadata();
      const MAX_DIMENSION = 2560; // Limite 2K

      if (metadata.width > MAX_DIMENSION || metadata.height > MAX_DIMENSION) {
        return setErrorAndRedirect(
          `Resolução muito alta (${metadata.width}x${metadata.height}px). O máximo permitido é 2560px.`
        );
      }

      // Se chegou aqui, deu tudo certo!
      req.session.success = "Imagem enviada com sucesso!";
      res.redirect("/admin");
    } catch (error) {
      console.error(error);
      setErrorAndRedirect("Erro interno ao processar a imagem.");
    }
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando em http://localhost:" + PORT);
});
