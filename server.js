
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

// Supabase existente
let supabase = null;

if (
  process.env.SUPABASE_URL &&
  process.env.SUPABASE_SECRET_KEY
) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
  );
}

// Interface do Suprema Studio
app.use(express.static(path.join(__dirname, "public")));

// Página inicial
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Saúde do servidor
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "online",
    supabaseConfigured: supabase !== null
  });
});

// Saúde do banco
app.get("/health/db", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({
      status: "error",
      databaseConnected: false
    });
  }

  try {
    const { error } = await supabase
      .from("games")
      .select("id")
      .limit(1);

    if (error) {
      console.error("Falha no teste do Supabase:", error.message);

      return res.status(503).json({
        status: "error",
        databaseConnected: false
      });
    }

    return res.status(200).json({
      status: "online",
      databaseConnected: true
    });
  } catch {
    console.error("Erro ao testar o Supabase.");

    return res.status(503).json({
      status: "error",
      databaseConnected: false
    });
  }
});

// Configuração OAuth do YouTube
function getYouTubeConfig() {
  const {
    YOUTUBE_CLIENT_ID,
    YOUTUBE_CLIENT_SECRET,
    YOUTUBE_REDIRECT_URI,
    YOUTUBE_OAUTH_STATE_SECRET
  } = process.env;

  if (
    !YOUTUBE_CLIENT_ID ||
    !YOUTUBE_CLIENT_SECRET ||
    !YOUTUBE_REDIRECT_URI ||
    !YOUTUBE_OAUTH_STATE_SECRET
  ) {
    return null;
  }

  return {
    clientId: YOUTUBE_CLIENT_ID,
    clientSecret: YOUTUBE_CLIENT_SECRET,
    redirectUri: YOUTUBE_REDIRECT_URI,
    stateSecret: YOUTUBE_OAUTH_STATE_SECRET
  };
}

const YOUTUBE_SCOPES = [
  "https://www.googleapis.com/auth/youtube.readonly",
  "https://www.googleapis.com/auth/yt-analytics.readonly"
];

function createSignedState(secret, payload) {
  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifySignedState(secret, value) {
  if (typeof value !== "string") {
    return null;
  }

  const parts = value.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [encoded, suppliedSignature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();

  let actualSignature;

  try {
    actualSignature = Buffer.from(
      suppliedSignature,
      "base64url"
    );
  } catch {
    return null;
  }

  if (
    actualSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(
      actualSignature,
      expectedSignature
    )
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (
      !Number.isFinite(payload.createdAt) ||
      Date.now() - payload.createdAt > 10 * 60 * 1000 ||
      Date.now() < payload.createdAt
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

// Inicia o OAuth do YouTube
app.get("/auth/youtube", (req, res) => {
  const config = getYouTubeConfig();

  if (!config) {
    return res.status(503).send(
      "A integração do YouTube ainda não está configurada no servidor."
    );
  }

  const state = createSignedState(config.stateSecret, {
    nonce: crypto.randomBytes(32).toString("hex"),
    createdAt: Date.now()
  });

  res.cookie("youtube_oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
    path: "/auth/youtube/callback"
  });

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: YOUTUBE_SCOPES.join(" "),
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    state
  });

  return res.redirect(
    `https://accounts.google.com/o/oauth2/v2/auth?${params}`
  );
});

// Recebe o retorno do Google
app.get("/auth/youtube/callback", async (req, res) => {
  const config = getYouTubeConfig();

  if (!config) {
    return res.status(503).send(
      "A integração do YouTube ainda não está configurada."
    );
  }

  const clearStateCookie = () => {
    res.clearCookie("youtube_oauth_state", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/auth/youtube/callback"
    });
  };

  const savedState = verifySignedState(
    config.stateSecret,
    req.cookies.youtube_oauth_state
  );

  const returnedState = verifySignedState(
    config.stateSecret,
    req.query.state
  );

  if (
    !savedState ||
    !returnedState ||
    savedState.nonce !== returnedState.nonce ||
    savedState.createdAt !== returnedState.createdAt
  ) {
    clearStateCookie();

    return res.status(400).send(
      "Solicitação OAuth inválida ou expirada. Volte ao Suprema Studio e tente novamente."
    );
  }

  clearStateCookie();

  if (req.query.error) {
    return res.status(400).send(
      "A autorização do YouTube foi cancelada ou recusada."
    );
  }

  if (typeof req.query.code !== "string") {
    return res.status(400).send(
      "O Google não retornou um código de autorização válido."
    );
  }

  try {
    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code: req.query.code,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          redirect_uri: config.redirectUri,
          grant_type: "authorization_code"
        })
      }
    );

    if (!tokenResponse.ok) {
      console.error(
        "Falha na troca do código OAuth. HTTP:",
        tokenResponse.status
      );

      return res.status(502).send(
        "Não foi possível concluir a autorização com o Google."
      );
    }

    const tokens = await tokenResponse.json();

    if (!tokens.access_token) {
      return res.status(502).send(
        "O Google não forneceu um token de acesso válido."
      );
    }

    const channelResponse = await fetch(
      "https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    if (!channelResponse.ok) {
      console.error(
        "Falha ao consultar o canal. HTTP:",
        channelResponse.status
      );

      return res.status(502).send(
        "A autorização foi recebida, mas não foi possível consultar o canal."
      );
    }

    const channelData = await channelResponse.json();
    const channel = channelData.items?.[0];

    if (!channel) {
      return res.status(404).send(
        "Nenhum canal do YouTube foi encontrado na conta autorizada."
      );
    }

    // Etapa inicial: não persistir tokens ainda.
    // A persistência será implementada após conferir
    // o esquema da tabela social_tokens.
    const title = escapeHtml(
      channel.snippet?.title || "Canal do YouTube"
    );
    const subscribers = escapeHtml(
      channel.statistics?.subscriberCount ?? "Não disponível"
    );
    const views = escapeHtml(
      channel.statistics?.viewCount ?? "Não disponível"
    );
    const videos = escapeHtml(
      channel.statistics?.videoCount ?? "Não disponível"
    );

    res.type("html").send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YouTube — Suprema Studio</title>
<style>
body{margin:0;background:#101010;color:#f5f5f5;font:16px Arial,sans-serif;display:grid;min-height:100vh;place-items:center}
main{max-width:440px;margin:24px;padding:28px;background:#1b1b1b;border:1px solid #333;border-radius:16px}
h1{font-size:24px}
p{line-height:1.6;color:#ccc}
strong{color:#ff5555}
a{display:inline-block;margin-top:12px;color:#fff;background:#d92735;padding:12px 18px;border-radius:8px;text-decoration:none}
</style>
</head>
<body>
<main>
<h1>Autorização recebida</h1>
<p>Canal autorizado: <strong>${title}</strong></p>
<p>Inscritos: ${subscribers}</p>
<p>Visualizações: ${views}</p>
<p>Vídeos: ${videos}</p>
<p>Esta é uma verificação inicial. A conexão permanente e a atualização automática ainda não foram configuradas.</p>
<a href="/">Voltar ao Suprema Studio</a>
</main>
</body>
</html>`);
  } catch (error) {
    console.error(
      "Erro interno na autorização do YouTube:",
      error.message
    );

    return res.status(500).send(
      "Ocorreu um erro interno durante a conexão. Tente novamente mais tarde."
    );
  }
});

// Inicialização
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor iniciado na porta ${PORT}`);
});
