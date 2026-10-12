
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

let supabase = null;

if (process.env.SUPABASE_URL && process.env.SUPABASE_SECRET_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );
}

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "online",
    supabaseConfigured: Boolean(supabase)
  });
});

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
    return res.status(503).json({
      status: "error",
      databaseConnected: false
    });
  }
});

// Configuração do YouTube
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

// Assinatura do estado OAuth contra adulteração
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
  if (typeof value !== "string") return null;

  const parts = value.split(".");
  if (parts.length !== 2) return null;

  const [encoded, suppliedSignature] = parts;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();

  let supplied;

  try {
    supplied = Buffer.from(suppliedSignature, "base64url");
  } catch {
    return null;
  }

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (
      typeof payload.userId !== "string" ||
      typeof payload.nonce !== "string" ||
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

// Chave de 32 bytes em Base64 para AES-256-GCM
function getEncryptionKey() {
  const value = process.env.YOUTUBE_TOKEN_ENCRYPTION_KEY;
  if (!value) return null;

  try {
    const key = Buffer.from(value, "base64");

    if (
      key.length !== 32 ||
      key.toString("base64") !== value
    ) {
      return null;
    }

    return key;
  } catch {
    return null;
  }
}

function encryptToken(value) {
  if (typeof value !== "string" || !value) return null;

  const key = getEncryptionKey();

  if (!key) {
    throw new Error("Chave de criptografia ausente ou inválida.");
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    "v1",
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url")
  ].join(":");
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

function resultPage(title, message) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — Suprema Studio</title>
<style>
body{margin:0;background:#101010;color:#f5f5f5;font:16px Arial,sans-serif;display:grid;min-height:100vh;place-items:center}
main{max-width:460px;margin:24px;padding:28px;background:#1b1b1b;border:1px solid #333;border-radius:16px}
h1{font-size:24px}
p{line-height:1.6;color:#ccc}
a{display:inline-block;margin-top:12px;color:#fff;background:#d92735;padding:12px 18px;border-radius:8px;text-decoration:none}
</style>
</head>
<body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a href="/">Voltar ao Suprema Studio</a></main></body>
</html>`;
}

// Início OAuth: exige uma sessão Supabase válida
app.post("/auth/youtube/start", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({
      error: "O serviço de autenticação não está configurado."
    });
  }

  const config = getYouTubeConfig();

  if (!config || !getEncryptionKey()) {
    return res.status(503).json({
      error: "A integração do YouTube não está configurada corretamente."
    });
  }

  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({
      error: "Entre na sua conta do Suprema Studio novamente."
    });
  }

  try {
    const { data, error } = await supabase.auth.getUser(match[1]);

    if (error || !data?.user?.id) {
      return res.status(401).json({
        error: "Sua sessão expirou. Entre novamente."
      });
    }

    const state = createSignedState(config.stateSecret, {
      userId: data.user.id,
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

    return res.json({
      url: `https://accounts.google.com/o/oauth2/v2/auth?${params}`
    });
  } catch (error) {
    console.error("Falha ao iniciar OAuth:", error.message);

    return res.status(500).json({
      error: "Não foi possível iniciar a conexão com o YouTube."
    });
  }
});

// Não permitir iniciar OAuth sem validar o usuário
app.get("/auth/youtube", (req, res) => {
  return res.status(405).send(
    "Inicie a conexão pelo botão autenticado dentro do Suprema Studio."
  );
});

// Retorno do Google: valida estado, consulta canal e persiste a conexão
app.get("/auth/youtube/callback", async (req, res) => {
  const config = getYouTubeConfig();

  const clearStateCookie = () => {
    res.clearCookie("youtube_oauth_state", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/auth/youtube/callback"
    });
  };

  if (!supabase || !config || !getEncryptionKey()) {
    clearStateCookie();

    return res.status(503).send(
      resultPage("Configuração incompleta", "A integração ainda não está pronta no servidor.")
    );
  }

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
    savedState.userId !== returnedState.userId ||
    savedState.nonce !== returnedState.nonce ||
    savedState.createdAt !== returnedState.createdAt
  ) {
    clearStateCookie();

    return res.status(400).send(
      resultPage("Solicitação inválida", "Volte ao Suprema Studio e tente conectar novamente.")
    );
  }

  clearStateCookie();

  if (req.query.error) {
    return res.status(400).send(
      resultPage("Conexão cancelada", "A autorização do YouTube foi cancelada ou recusada.")
    );
  }

  if (typeof req.query.code !== "string") {
    return res.status(400).send(
      resultPage("Código inválido", "O Google não retornou um código válido.")
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
      console.error("Falha na troca OAuth. HTTP:", tokenResponse.status);

      return res.status(502).send(
        resultPage("Falha na autorização", "Não foi possível concluir a autorização com o Google.")
      );
    }

    const tokens = await tokenResponse.json();

    if (!tokens.access_token) {
      return res.status(502).send(
        resultPage("Token ausente", "O Google não forneceu um token de acesso.")
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
      console.error("Falha ao consultar canal. HTTP:", channelResponse.status);

      return res.status(502).send(
        resultPage("Canal não consultado", "A autorização foi recebida, mas não foi possível consultar o canal.")
      );
    }

    const channelData = await channelResponse.json();
    const channel = channelData.items?.[0];

    if (!channel?.id) {
      return res.status(404).send(
        resultPage("Canal não encontrado", "Nenhum canal foi encontrado na conta autorizada.")
      );
    }

    // A identidade do usuário vem do estado assinado pelo servidor,
    // nunca de um user_id enviado pelo navegador.
    const accountPayload = {
      user_id: savedState.userId,
      platform: "youtube",
      external_id: channel.id,
      display_name: channel.snippet?.title || "Canal do YouTube",
      scopes: typeof tokens.scope === "string"
        ? tokens.scope.split(" ")
        : YOUTUBE_SCOPES,
      status: "connected",
      last_sync_at: new Date().toISOString()
    };

    const { data: account, error: accountError } = await supabase
      .from("social_accounts")
      .upsert(accountPayload, {
        onConflict: "user_id,platform,external_id"
      })
      .select("id")
      .single();

    if (accountError || !account?.id) {
      console.error(
        "Falha ao salvar conta social:",
        accountError?.message || "Conta não retornada"
      );

      return res.status(500).send(
        resultPage("Falha ao salvar conta", "O canal foi autorizado, mas não foi possível salvar a conta. Tente novamente.")
      );
    }

    // Se o Google não enviar um novo refresh_token, preservar o anterior.
    const { data: previousTokens, error: previousError } = await supabase
      .from("social_tokens")
      .select("refresh_token_enc")
      .eq("account_id", account.id)
      .maybeSingle();

    if (previousError) {
      console.error("Falha ao consultar tokens anteriores:", previousError.message);

      return res.status(500).send(
        resultPage("Falha ao salvar tokens", "Não foi possível consultar a conexão existente.")
      );
    }

    const refreshTokenEnc = tokens.refresh_token
      ? encryptToken(tokens.refresh_token)
      : (previousTokens?.refresh_token_enc || null);

    const tokenPayload = {
      account_id: account.id,
      access_token_enc: encryptToken(tokens.access_token),
      refresh_token_enc: refreshTokenEnc,
      expires_at: new Date(
        Date.now() + (Number(tokens.expires_in) || 3600) * 1000
      ).toISOString()
    };

    const { error: tokenError } = await supabase
      .from("social_tokens")
      .upsert(tokenPayload, {
        onConflict: "account_id"
      });

    if (tokenError) {
      console.error("Falha ao salvar tokens:", tokenError.message);

      return res.status(500).send(
        resultPage("Falha ao salvar tokens", "A conta foi identificada, mas não foi possível concluir o armazenamento seguro dos tokens.")
      );
    }

    return res.status(200).send(
      resultPage(
        "YouTube conectado!",
        `O canal ${channel.snippet?.title || "do YouTube"} foi vinculado à sua conta do Suprema Studio. Os tokens foram armazenados criptografados.`
      )
    );
  } catch (error) {
    console.error("Erro interno no OAuth do YouTube:", error.message);

    return res.status(500).send(
      resultPage("Erro na conexão", "Ocorreu um erro interno. Tente novamente mais tarde.")
    );
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor iniciado na porta ${PORT}`);
});
