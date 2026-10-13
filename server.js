
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "100kb" }));
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
  } catch (error) {
    return res.status(503).json({
      status: "error",
      databaseConnected: false
    });
  }
});

// --------------------------------------------------
// CONFIGURAÇÃO DO YOUTUBE
// --------------------------------------------------

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

// --------------------------------------------------
// AUTENTICAÇÃO DO USUÁRIO SUPABASE
// --------------------------------------------------

async function getAuthenticatedUser(req) {
  if (!supabase) return null;

  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) return null;

  const { data, error } = await supabase.auth.getUser(match[1]);

  if (error || !data?.user?.id) return null;

  return data.user;
}

// --------------------------------------------------
// ESTADO ASSINADO DO OAUTH
// --------------------------------------------------

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

// --------------------------------------------------
// CRIPTOGRAFIA DOS TOKENS
// --------------------------------------------------

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

  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    encrypted.toString("base64url")
  ].join(":");
}

function decryptToken(value) {
  if (typeof value !== "string" || !value) return null;

  const key = getEncryptionKey();

  if (!key) {
    throw new Error("Chave de criptografia ausente ou inválida.");
  }

  const parts = value.split(":");

  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("Formato de token criptografado inválido.");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const encrypted = Buffer.from(parts[3], "base64url");

  if (iv.length !== 12 || tag.length !== 16) {
    throw new Error("Dados criptografados inválidos.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}

// --------------------------------------------------
// UTILITÁRIOS
// --------------------------------------------------

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

// --------------------------------------------------
// RENOVAÇÃO DO ACCESS TOKEN
// --------------------------------------------------

async function refreshYouTubeAccessToken(accountId) {
  if (!supabase) {
    throw new Error("Supabase não configurado.");
  }

  const config = getYouTubeConfig();

  if (!config || !getEncryptionKey()) {
    throw new Error("Configuração do YouTube incompleta.");
  }

  const { data: saved, error: savedError } = await supabase
    .from("social_tokens")
    .select("refresh_token_enc")
    .eq("account_id", accountId)
    .maybeSingle();

  if (savedError) throw savedError;

  if (!saved?.refresh_token_enc) {
    const error = new Error("Não existe refresh token salvo.");
    error.code = "NO_REFRESH_TOKEN";
    throw error;
  }

  const refreshToken = decryptToken(saved.refresh_token_enc);

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        refresh_token: refreshToken,
        grant_type: "refresh_token"
      })
    }
  );

  const result = await response.json();

  if (!response.ok || !result.access_token) {
    const error = new Error("O Google não renovou o token.");
    error.code = result.error || "REFRESH_FAILED";
    throw error;
  }

  const expiresAt = new Date(
    Date.now() + (Number(result.expires_in) || 3600) * 1000
  ).toISOString();

  const tokenPayload = {
    account_id: accountId,
    access_token_enc: encryptToken(result.access_token),
    refresh_token_enc: saved.refresh_token_enc,
    expires_at: expiresAt
  };

  const { error: updateError } = await supabase
    .from("social_tokens")
    .upsert(tokenPayload, {
      onConflict: "account_id"
    });

  if (updateError) throw updateError;

  return {
    accessToken: result.access_token,
    expiresAt
  };
}

// --------------------------------------------------
// STATUS PERSISTENTE DO YOUTUBE
// --------------------------------------------------

app.get("/api/youtube/status", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Sessão inválida. Entre novamente no Suprema Studio."
      });
    }

    const { data: account, error: accountError } = await supabase
      .from("social_accounts")
      .select("id, display_name, external_id, status, last_sync_at")
      .eq("user_id", user.id)
      .eq("platform", "youtube")
      .order("last_sync_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (accountError) {
      console.error("Falha ao consultar conta YouTube:", accountError.message);
      return res.status(500).json({
        error: "Não foi possível consultar a conexão do YouTube."
      });
    }

    if (!account) {
      return res.json({ connected: false });
    }

    if (account.status !== "connected") {
      return res.json({
        connected: false,
        needsReconnect: true,
        channelName: account.display_name
      });
    }

    const { data: tokenRecord, error: tokenError } = await supabase
      .from("social_tokens")
      .select("expires_at, refresh_token_enc, access_token_enc")
      .eq("account_id", account.id)
      .maybeSingle();

    if (tokenError) {
      console.error("Falha ao consultar tokens YouTube:", tokenError.message);
      return res.status(500).json({
        error: "Não foi possível verificar a autorização do YouTube."
      });
    }

    if (!tokenRecord?.refresh_token_enc || !tokenRecord?.access_token_enc) {
      return res.json({
        connected: false,
        needsReconnect: true,
        channelName: account.display_name
      });
    }

    const expiration = tokenRecord.expires_at
      ? new Date(tokenRecord.expires_at).getTime()
      : 0;

    // Renova quando faltarem menos de 60 segundos para expirar.
    if (!Number.isFinite(expiration) || expiration <= Date.now() + 60000) {
      try {
        await refreshYouTubeAccessToken(account.id);
      } catch (error) {
        console.error(
          "Falha ao renovar token YouTube:",
          error.code || error.message
        );

        if (
          error.code === "invalid_grant" ||
          error.code === "NO_REFRESH_TOKEN"
        ) {
          await supabase
            .from("social_accounts")
            .update({ status: "reconnect_required" })
            .eq("id", account.id)
            .eq("user_id", user.id);

          return res.json({
            connected: false,
            needsReconnect: true,
            channelName: account.display_name
          });
        }

        // Erros temporários não significam necessariamente
        // que o usuário precisa autorizar novamente.
        return res.status(503).json({
          error: "Não foi possível renovar o acesso ao YouTube agora.",
          retryable: true
        });
      }
    }

    return res.json({
      connected: true,
      channelName: account.display_name,
      channelId: account.external_id,
      status: "connected",
      lastSyncAt: account.last_sync_at
    });
  } catch (error) {
    console.error("Erro no status YouTube:", error.message);

    return res.status(500).json({
      error: "Erro interno ao verificar o YouTube."
    });
  }
});


// --------------------------------------------------
// ANALYTICS REAL DO CANAL YOUTUBE
// --------------------------------------------------
app.get("/api/youtube/analytics", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: "Sessão inválida. Entre novamente no Suprema Studio." });
    }
    if (!supabase) {
      return res.status(503).json({ error: "Banco de dados não configurado." });
    }

    const { data: account, error: accountError } = await supabase
      .from("social_accounts")
      .select("id, display_name, external_id, status")
      .eq("user_id", user.id)
      .eq("platform", "youtube")
      .order("last_sync_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (accountError) throw accountError;
    if (!account || account.status !== "connected") {
      return res.status(409).json({
        error: "O canal do YouTube não está conectado. Volte ao painel principal e conecte a conta.",
        needsReconnect: true
      });
    }

    const { data: tokenRecord, error: tokenError } = await supabase
      .from("social_tokens")
      .select("expires_at, access_token_enc, refresh_token_enc")
      .eq("account_id", account.id)
      .maybeSingle();

    if (tokenError) throw tokenError;
    if (!tokenRecord?.access_token_enc || !tokenRecord?.refresh_token_enc) {
      return res.status(409).json({
        error: "A autorização do YouTube está incompleta. Reconecte seu canal.",
        needsReconnect: true
      });
    }

    let accessToken;
    const expiration = tokenRecord.expires_at ? new Date(tokenRecord.expires_at).getTime() : 0;
    if (!Number.isFinite(expiration) || expiration <= Date.now() + 60000) {
      const refreshed = await refreshYouTubeAccessToken(account.id);
      accessToken = refreshed.accessToken;
    } else {
      accessToken = decryptToken(tokenRecord.access_token_enc);
    }

    const now = new Date();
    const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1));
    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - 27);
    const fmt = d => d.toISOString().slice(0, 10);

    const analyticsUrl = new URL("https://youtubeanalytics.googleapis.com/v2/reports");
    analyticsUrl.search = new URLSearchParams({
      ids: "channel==MINE",
      startDate: fmt(start),
      endDate: fmt(end),
      metrics: "views,estimatedMinutesWatched,subscribersGained,subscribersLost"
    }).toString();

    const previousEnd = new Date(start); previousEnd.setUTCDate(previousEnd.getUTCDate() - 1);
    const previousStart = new Date(previousEnd); previousStart.setUTCDate(previousStart.getUTCDate() - 27);
    const previousUrl = new URL("https://youtubeanalytics.googleapis.com/v2/reports");
    previousUrl.search = new URLSearchParams({ ids: "channel==MINE", startDate: fmt(previousStart), endDate: fmt(previousEnd), metrics: "views,estimatedMinutesWatched,subscribersGained,subscribersLost" }).toString();
    const dailyUrl = new URL("https://youtubeanalytics.googleapis.com/v2/reports");
    dailyUrl.search = new URLSearchParams({ ids: "channel==MINE", startDate: fmt(start), endDate: fmt(end), metrics: "views", dimensions: "day", sort: "day" }).toString();
    const rankingUrl = new URL("https://youtubeanalytics.googleapis.com/v2/reports");
    rankingUrl.search = new URLSearchParams({ ids: "channel==MINE", startDate: fmt(start), endDate: fmt(end), metrics: "views,likes,subscribersGained", dimensions: "video", sort: "-views", maxResults: "50" }).toString();
    const [analyticsResponse, channelResponse, dailyResponse, previousResponse, rankingResponse] = await Promise.all([
      fetch(analyticsUrl, { headers: { Authorization: `Bearer ${accessToken}` } }),
      fetch("https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true", { headers: { Authorization: `Bearer ${accessToken}` } }),
      fetch(dailyUrl, { headers: { Authorization: `Bearer ${accessToken}` } }),
      fetch(previousUrl, { headers: { Authorization: `Bearer ${accessToken}` } }),
      fetch(rankingUrl, { headers: { Authorization: `Bearer ${accessToken}` } })
    ]);
    const analyticsData = await analyticsResponse.json().catch(() => ({}));
    const channelData = await channelResponse.json().catch(() => ({}));
    const dailyData = await dailyResponse.json().catch(() => ({}));
    const previousData = await previousResponse.json().catch(() => ({}));
    const rankingData = await rankingResponse.json().catch(() => ({}));
    // O relatório Analytics fornece IDs e métricas, mas não o status de privacidade.
    // Buscamos metadados dos IDs retornados para excluir não listados/privados e obter títulos
    // mesmo quando o conteúdo não aparece nos 50 uploads recentes carregados na outra aba.
    let rankingItems = [];
    let rankingMetadataAvailable = true;
    if (rankingResponse.ok) {
      const rankingRows = rankingData.rows || [];
      const rankingIds = [...new Set(rankingRows.map(r => String(r[0] || "")).filter(Boolean))];
      if (rankingIds.length) {
        try {
          const detailsUrl = "https://www.googleapis.com/youtube/v3/videos?part=snippet,contentDetails,status,liveStreamingDetails&id=" + rankingIds.map(encodeURIComponent).join(",");
          const detailsResponse = await fetch(detailsUrl, { headers: { Authorization: `Bearer ${accessToken}` } });
          const detailsData = await detailsResponse.json().catch(() => ({}));
          if (!detailsResponse.ok) rankingMetadataAvailable = false;
          else {
            const detailsById = new Map((detailsData.items || []).map(v => [v.id, v]));
            rankingItems = rankingRows.map(r => {
              const video = detailsById.get(String(r[0] || ""));
              if (!video || video.status?.privacyStatus !== "public") return null;
              const duration = video.contentDetails?.duration || null;
              const seconds = durationToSeconds(duration);
              const isLive = Boolean(video.liveStreamingDetails) || ["live", "upcoming"].includes(video.snippet?.liveBroadcastContent);
              const type = isLive ? "live" : (seconds !== null && seconds <= 180 ? "short" : "video");
              return {
                videoId: video.id,
                title: video.snippet?.title || "Vídeo sem título",
                thumbnail: video.snippet?.thumbnails?.medium?.url || video.snippet?.thumbnails?.default?.url || null,
                publishedAt: video.snippet?.publishedAt || null,
                type,
                privacyStatus: video.status?.privacyStatus,
                views: Number(r[1] || 0),
                likes: Number(r[2] || 0),
                subscribersGained: Number(r[3] || 0)
              };
            }).filter(Boolean).sort((a, b) => b.views - a.views).slice(0, 10);
          }
        } catch (metadataError) {
          rankingMetadataAvailable = false;
          console.error("Não foi possível validar privacidade do ranking YouTube:", metadataError.message);
        }
      }
    }

    if (!analyticsResponse.ok) {
      console.error("YouTube Analytics API:", analyticsData.error?.message || analyticsResponse.status);
      const status = analyticsResponse.status === 401 || analyticsResponse.status === 403 ? 502 : analyticsResponse.status;
      return res.status(status).json({
        error: analyticsData.error?.message || "Não foi possível consultar o YouTube Analytics. Verifique as permissões da API e tente novamente.",
        apiStatus: analyticsResponse.status,
        retryable: analyticsResponse.status >= 500
      });
    }
    if (!channelResponse.ok) {
      console.error("YouTube Data API:", channelData.error?.message || channelResponse.status);
    }

    const row = analyticsData.rows?.[0] || [];
    const stats = channelData.items?.[0]?.statistics || {};
    const channelName = channelData.items?.[0]?.snippet?.title || account.display_name || "Canal do YouTube";

    return res.json({
      channelName,
      channelAvatar: channelData.items?.[0]?.snippet?.thumbnails?.high?.url || channelData.items?.[0]?.snippet?.thumbnails?.default?.url || null,
      period: { startDate: fmt(start), endDate: fmt(end), previousStartDate: fmt(previousStart), previousEndDate: fmt(previousEnd) },
      daily: (dailyData.rows || []).map(r => ({ date: r[0], views: Number(r[1] || 0) })),
      previousMetrics: (() => { const r = previousData.rows?.[0] || []; return { views: Number(r[0] || 0), estimatedMinutesWatched: Number(r[1] || 0), subscribersGained: Number(r[2] || 0), subscribersLost: Number(r[3] || 0), available: previousResponse.ok }; })(),
      ranking: rankingItems,
      rankingAvailable: rankingResponse.ok && rankingMetadataAvailable,
      rankingPublicOnly: true,
      metrics: {
        views: Number(row[0] || 0),
        channelTotalViews: Number(stats.viewCount || 0),
        estimatedMinutesWatched: Number(row[1] || 0),
        subscribersGained: Number(row[2] || 0),
        subscribersLost: Number(row[3] || 0),
        subscribers: stats.hiddenSubscriberCount ? null : Number(stats.subscriberCount || 0)
      },
      source: "YouTube Analytics API",
      updatedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error("Erro ao consultar analytics YouTube:", error.code || error.message);
    return res.status(500).json({
      error: "Não foi possível carregar as métricas agora. Tente novamente em instantes.",
      retryable: true
    });
  }
});

// --------------------------------------------------
// DADOS DO CANAL, VÍDEOS/SHORTS E COMENTÁRIOS
// --------------------------------------------------
async function getYouTubeContext(req) {
  const user = await getAuthenticatedUser(req);
  if (!user) return { error: { status: 401, message: "Sessão inválida. Entre novamente no Suprema Studio." } };
  if (!supabase) return { error: { status: 503, message: "Banco de dados não configurado." } };
  const { data: account, error: accountError } = await supabase
    .from("social_accounts")
    .select("id, display_name, external_id, status")
    .eq("user_id", user.id).eq("platform", "youtube")
    .order("last_sync_at", { ascending: false }).limit(1).maybeSingle();
  if (accountError) throw accountError;
  if (!account || account.status !== "connected") return { error: { status: 409, message: "O canal do YouTube não está conectado.", needsReconnect: true } };
  const { data: tokenRecord, error: tokenError } = await supabase
    .from("social_tokens").select("expires_at, access_token_enc, refresh_token_enc")
    .eq("account_id", account.id).maybeSingle();
  if (tokenError) throw tokenError;
  if (!tokenRecord?.access_token_enc || !tokenRecord?.refresh_token_enc) return { error: { status: 409, message: "A autorização do YouTube está incompleta. Reconecte o canal.", needsReconnect: true } };
  const expiration = tokenRecord.expires_at ? new Date(tokenRecord.expires_at).getTime() : 0;
  const accessToken = (!Number.isFinite(expiration) || expiration <= Date.now() + 60000)
    ? (await refreshYouTubeAccessToken(account.id)).accessToken
    : decryptToken(tokenRecord.access_token_enc);
  return { user, account, accessToken };
}

async function youtubeJson(url, accessToken) {
  const response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` }, cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.error?.message || `YouTube API retornou HTTP ${response.status}`);
    err.status = response.status; throw err;
  }
  return data;
}

app.get("/api/youtube/content", async (req, res) => {
  try {
    const ctx = await getYouTubeContext(req);
    if (ctx.error) return res.status(ctx.error.status).json(ctx.error);
    const { accessToken, account } = ctx;
    const channelData = await youtubeJson("https://www.googleapis.com/youtube/v3/channels?part=snippet,brandingSettings,statistics,contentDetails&mine=true", accessToken);
    const channel = channelData.items?.[0];
    if (!channel) return res.status(404).json({ error: "Não foi possível encontrar o canal autorizado." });
    const uploads = channel.contentDetails?.relatedPlaylists?.uploads;
    let videos = [];
    if (uploads) {
      const playlist = await youtubeJson("https://www.googleapis.com/youtube/v3/playlistItems?part=snippet,contentDetails&playlistId=" + encodeURIComponent(uploads) + "&maxResults=50", accessToken);
      const ids = (playlist.items || []).map(x => x.contentDetails?.videoId || x.snippet?.resourceId?.videoId).filter(Boolean);
      if (ids.length) {
        const detail = await youtubeJson("https://www.googleapis.com/youtube/v3/videos?part=snippet,statistics,contentDetails,status,liveStreamingDetails&id=" + ids.map(encodeURIComponent).join(","), accessToken);
        videos = (detail.items || []).map(v => {
          const duration = v.contentDetails?.duration || null;
          const seconds = durationToSeconds(duration);
          const isLive = Boolean(v.liveStreamingDetails) || v.snippet?.liveBroadcastContent === "live" || v.snippet?.liveBroadcastContent === "upcoming";
          // A Data API v3 não expõe um sinal universal e confiável de “é Short”.
          // Até 180 s é usado como classificação prática, não como confirmação do formato vertical.
          const type = isLive ? "live" : (seconds !== null && seconds <= 180 ? "short" : "video");
          return {
            id: v.id,
            title: v.snippet?.title || "Vídeo sem título",
            description: v.snippet?.description || "",
            publishedAt: v.snippet?.publishedAt || null,
            thumbnail: v.snippet?.thumbnails?.medium?.url || v.snippet?.thumbnails?.default?.url || null,
            url: "https://www.youtube.com/watch?v=" + v.id,
            views: Number(v.statistics?.viewCount || 0),
            likes: Number(v.statistics?.likeCount || 0),
            comments: Number(v.statistics?.commentCount || 0),
            duration,
            durationSeconds: seconds,
            type,
            liveBroadcastContent: v.snippet?.liveBroadcastContent || "none",
            privacyStatus: v.status?.privacyStatus || "unknown"
          };
        });
      }
    }
    return res.json({
      channel: { id: channel.id, title: channel.snippet?.title || account.display_name, avatar: channel.snippet?.thumbnails?.high?.url || channel.snippet?.thumbnails?.default?.url || null, banner: channel.brandingSettings?.image?.bannerExternalUrl || null, subscribers: channel.statistics?.hiddenSubscriberCount ? null : Number(channel.statistics?.subscriberCount || 0), totalViews: Number(channel.statistics?.viewCount || 0), videoCount: Number(channel.statistics?.videoCount || 0) },
      videos,
      viewCountNote: "As visualizações por conteúdo e o total do canal são contagens acumuladas da YouTube Data API; não são o mesmo que visualizações dos últimos 28 dias no YouTube Analytics.",
      updatedAt: new Date().toISOString(),
      source: "YouTube Data API v3"
    });
  } catch (error) {
    console.error("Erro ao carregar conteúdo YouTube:", error.message);
    return res.status(error.status || 500).json({ error: error.message || "Não foi possível carregar o conteúdo do YouTube." });
  }
});

function durationToSeconds(duration) {
  if (!duration || typeof duration !== "string") return null;
  const match = duration.match(/^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/);
  if (!match) return null;
  return Number(match[1] || 0) * 3600 + Number(match[2] || 0) * 60 + Number(match[3] || 0);
}

app.get("/api/youtube/community", async (req, res) => {
  try {
    const ctx = await getYouTubeContext(req);
    if (ctx.error) return res.status(ctx.error.status).json(ctx.error);

    // Estratégia principal: obter os vídeos recentes do canal e consultar comentários
    // por videoId. Isso evita depender exclusivamente do filtro de canal, que pode falhar
    // em alguns contextos, e permite ignorar vídeos com comentários desativados.
    const channelData = await youtubeJson("https://www.googleapis.com/youtube/v3/channels?part=id,contentDetails&mine=true", ctx.accessToken);
    const channel = channelData.items?.[0];
    const uploads = channel?.contentDetails?.relatedPlaylists?.uploads;
    if (!channel?.id || !uploads) return res.status(404).json({ error: "Não foi possível identificar o canal e a lista de vídeos da conta autorizada." });

    const playlist = await youtubeJson("https://www.googleapis.com/youtube/v3/playlistItems?part=snippet,contentDetails&playlistId=" + encodeURIComponent(uploads) + "&maxResults=50", ctx.accessToken);
    const entries = (playlist.items || []).map(x => ({ id: x.contentDetails?.videoId || x.snippet?.resourceId?.videoId, title: x.snippet?.title || "Vídeo do canal" })).filter(x => x.id);
    const videos = entries.slice(0, 30);
    const results = await Promise.all(videos.map(async video => {
      try {
        const url = "https://www.googleapis.com/youtube/v3/commentThreads?part=snippet,replies&videoId=" + encodeURIComponent(video.id) + "&order=time&maxResults=100&textFormat=plainText";
        const data = await youtubeJson(url, ctx.accessToken);
        return (data.items || []).map(item => {
          const c = item.snippet?.topLevelComment;
          const s = c?.snippet || {};
          return { id: c?.id || item.id, videoId: video.id, videoTitle: video.title, author: s.authorDisplayName || "Usuário", authorAvatar: s.authorProfileImageUrl || null, text: s.textDisplay || s.textOriginal || "", publishedAt: s.publishedAt || null, likeCount: Number(s.likeCount || 0), replyCount: Number(item.snippet?.totalReplyCount || 0), canReply: Boolean(item.snippet?.canReply) };
        });
      } catch (error) {
        // Comentários desativados num vídeo não devem bloquear os demais.
        if (error.status === 403 || error.status === 404) return [];
        throw error;
      }
    }));
    const comments = results.flat().sort((a, b) => new Date(b.publishedAt || 0) - new Date(a.publishedAt || 0)).slice(0, 100);
    return res.json({ comments, scannedVideos: videos.length, updatedAt: new Date().toISOString(), source: "YouTube Data API v3" });
  } catch (error) {
    console.error("Erro ao carregar comunidade YouTube:", error.message);
    let message = error.message || "Não foi possível carregar os comentários.";
    if (error.status === 403) message = "O YouTube recusou a consulta de comentários (403). Confirme se o escopo youtube.readonly foi autorizado e se a API está habilitada no projeto Google. O erro técnico foi registrado no servidor.";
    return res.status(error.status || 500).json({ error: message });
  }
});

// --------------------------------------------------
// INÍCIO DO OAUTH
// --------------------------------------------------

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

  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Entre na sua conta do Suprema Studio novamente."
      });
    }

    const state = createSignedState(config.stateSecret, {
      userId: user.id,
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

// --------------------------------------------------
// RETORNO DO GOOGLE E PERSISTÊNCIA DA CONTA
// --------------------------------------------------

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
      resultPage(
        "Configuração incompleta",
        "A integração ainda não está pronta no servidor."
      )
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
      resultPage(
        "Solicitação inválida",
        "Volte ao Suprema Studio e tente conectar novamente."
      )
    );
  }

  clearStateCookie();

  if (req.query.error) {
    return res.status(400).send(
      resultPage(
        "Conexão cancelada",
        "A autorização do YouTube foi cancelada ou recusada."
      )
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

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      console.error("Falha na troca OAuth. HTTP:", tokenResponse.status);

      return res.status(502).send(
        resultPage(
          "Falha na autorização",
          "Não foi possível concluir a autorização com o Google."
        )
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
        resultPage(
          "Canal não consultado",
          "A autorização foi recebida, mas não foi possível consultar o canal."
        )
      );
    }

    const channelData = await channelResponse.json();
    const channel = channelData.items?.[0];

    if (!channel?.id) {
      return res.status(404).send(
        resultPage(
          "Canal não encontrado",
          "Nenhum canal foi encontrado na conta autorizada."
        )
      );
    }

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
        resultPage(
          "Falha ao salvar conta",
          "O canal foi autorizado, mas não foi possível salvar a conta."
        )
      );
    }

    const { data: previousTokens, error: previousError } = await supabase
      .from("social_tokens")
      .select("refresh_token_enc")
      .eq("account_id", account.id)
      .maybeSingle();

    if (previousError) {
      console.error("Falha ao consultar tokens anteriores:", previousError.message);

      return res.status(500).send(
        resultPage(
          "Falha ao salvar tokens",
          "Não foi possível consultar a conexão existente."
        )
      );
    }

    const refreshTokenEnc = tokens.refresh_token
      ? encryptToken(tokens.refresh_token)
      : (previousTokens?.refresh_token_enc || null);

    if (!refreshTokenEnc) {
      return res.status(502).send(
        resultPage(
          "Autorização incompleta",
          "O Google não forneceu um refresh token. Tente conectar novamente."
        )
      );
    }

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
        resultPage(
          "Falha ao salvar tokens",
          "A conta foi identificada, mas não foi possível concluir o armazenamento seguro dos tokens."
        )
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
      resultPage(
        "Erro na conexão",
        "Ocorreu um erro interno. Tente novamente mais tarde."
      )
    );
  }
});


// --------------------------------------------------
// TWITCH STUDIO — OAuth, conta conectada e dados reais
// --------------------------------------------------
function getTwitchConfig() {
  const { TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, TWITCH_REDIRECT_URI } = process.env;
  const stateSecret = process.env.TWITCH_OAUTH_STATE_SECRET || process.env.YOUTUBE_OAUTH_STATE_SECRET;
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET || !TWITCH_REDIRECT_URI || !stateSecret) return null;
  return { clientId: TWITCH_CLIENT_ID, clientSecret: TWITCH_CLIENT_SECRET, redirectUri: TWITCH_REDIRECT_URI, stateSecret };
}

async function getTwitchAccountContext(req) {
  const user = await getAuthenticatedUser(req);
  if (!user) { const e = new Error('Entre novamente no Suprema Studio.'); e.status = 401; throw e; }
  if (!supabase) { const e = new Error('Supabase não está configurado.'); e.status = 503; throw e; }
  const { data: account, error } = await supabase.from('social_accounts').select('id, external_id, display_name, status, last_sync_at').eq('user_id', user.id).eq('platform', 'twitch').order('last_sync_at', { ascending: false }).limit(1).maybeSingle();
  if (error) throw error;
  if (!account) return { user, account: null, accessToken: null };
  const { data: tokenRow, error: tokenError } = await supabase.from('social_tokens').select('access_token_enc, expires_at').eq('account_id', account.id).maybeSingle();
  if (tokenError) throw tokenError;
  if (!tokenRow?.access_token_enc) return { user, account, accessToken: null };
  let token = decryptToken(tokenRow.access_token_enc);
  if (tokenRow.expires_at && new Date(tokenRow.expires_at).getTime() < Date.now() + 60000) {
    const cfg = getTwitchConfig();
    if (!cfg) return { user, account, accessToken: null };
    const r = await fetch('https://id.twitch.tv/oauth2/validate', { headers: { Authorization: `OAuth ${token}` } });
    if (!r.ok) return { user, account, accessToken: null };
  }
  return { user, account, accessToken: token };
}

app.get('/api/twitch/status', async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) return res.status(401).json({ error: 'Sessão inválida. Entre novamente no Suprema Studio.' });
    const { data: account, error } = await supabase.from('social_accounts').select('id, external_id, display_name, status, last_sync_at').eq('user_id', user.id).eq('platform', 'twitch').order('last_sync_at', { ascending: false }).limit(1).maybeSingle();
    if (error) throw error;
    if (!account) return res.json({ connected: false, configured: Boolean(getTwitchConfig()) });
    const { data: tokenRow, error: tokenError } = await supabase.from('social_tokens').select('access_token_enc, expires_at').eq('account_id', account.id).maybeSingle();
    if (tokenError) throw tokenError;
    let valid = false;
    if (tokenRow?.access_token_enc) {
      try { const token = decryptToken(tokenRow.access_token_enc); const vr = await fetch('https://id.twitch.tv/oauth2/validate', { headers: { Authorization: `OAuth ${token}` } }); valid = vr.ok; } catch (_) {}
    }
    return res.json({ connected: valid, configured: Boolean(getTwitchConfig()), accountId: account.external_id, displayName: account.display_name, lastSyncAt: account.last_sync_at, needsReconnect: !valid });
  } catch (e) { console.error('Twitch status:', e.message); return res.status(e.status || 500).json({ error: e.status ? e.message : 'Não foi possível verificar a conexão Twitch.' }); }
});

app.get('/api/twitch/content', async (req, res) => {
  try {
    const ctx = await getTwitchAccountContext(req);
    if (!ctx.account || !ctx.accessToken) return res.status(409).json({ error: 'Conecte ou reconecte sua conta Twitch.' });
    const cfg = getTwitchConfig();
    const headers = { 'Client-Id': cfg.clientId, Authorization: `Bearer ${ctx.accessToken}` };
    const vr = await fetch('https://id.twitch.tv/oauth2/validate', { headers: { Authorization: `OAuth ${ctx.accessToken}` } });
    if (!vr.ok) return res.status(401).json({ error: 'A autorização expirou. Reconecte a Twitch.' });
    const profileResponse = await fetch(`https://api.twitch.tv/helix/users?id=${encodeURIComponent(ctx.account.external_id)}`, { headers });
    const profileData = await profileResponse.json();
    if (!profileResponse.ok) throw new Error(profileData.message || 'Falha ao consultar perfil Twitch.');
    const profile = profileData.data?.[0];
    if (!profile) return res.status(404).json({ error: 'Perfil Twitch não encontrado.' });
    const streamsResponse = await fetch(`https://api.twitch.tv/helix/streams?user_id=${encodeURIComponent(profile.id)}&first=10`, { headers });
    const streamsData = await streamsResponse.json();
    if (!streamsResponse.ok) throw new Error(streamsData.message || 'Falha ao consultar transmissões.');
    const videosResponse = await fetch(`https://api.twitch.tv/helix/videos?user_id=${encodeURIComponent(profile.id)}&first=20&type=archive`, { headers });
    const videosData = await videosResponse.json();
    if (!videosResponse.ok) throw new Error(videosData.message || 'Falha ao consultar vídeos/VODs.');
    const gamesResponse = await fetch(`https://api.twitch.tv/helix/channels?broadcaster_id=${encodeURIComponent(profile.id)}`, { headers });
    const gamesData = await gamesResponse.json();
    return res.json({ profile: { id: profile.id, login: profile.login, displayName: profile.display_name, description: profile.description, profileImageUrl: profile.profile_image_url, broadcasterType: profile.broadcaster_type, viewCount: profile.view_count, createdAt: profile.created_at }, streams: streamsData.data || [], videos: videosData.data || [], channel: gamesData.data?.[0] || null, fetchedAt: new Date().toISOString(), limitations: ['A API Helix não disponibiliza contagem de seguidores em todos os cenários com o escopo básico. O painel não inventa esse número.', 'Estatísticas avançadas e dados históricos podem exigir permissões adicionais ou endpoints específicos.'] });
  } catch (e) { console.error('Twitch content:', e.message); return res.status(e.status || 502).json({ error: e.status ? e.message : 'Não foi possível carregar os dados da Twitch.' }); }
});

app.post('/auth/twitch/start', async (req, res) => {
  const cfg = getTwitchConfig();
  if (!supabase || !cfg || !getEncryptionKey()) return res.status(503).json({ error: 'Configure TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, TWITCH_REDIRECT_URI, TWITCH_OAUTH_STATE_SECRET e a chave de criptografia no servidor.' });
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) return res.status(401).json({ error: 'Entre novamente no Suprema Studio.' });
    const state = createSignedState(cfg.stateSecret, { userId: user.id, nonce: crypto.randomBytes(32).toString('hex'), createdAt: Date.now() });
    res.cookie('twitch_oauth_state', state, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/auth/twitch/callback' });
    const params = new URLSearchParams({ client_id: cfg.clientId, redirect_uri: cfg.redirectUri, response_type: 'code', scope: 'user:read:email', state });
    return res.json({ url: `https://id.twitch.tv/oauth2/authorize?${params}` });
  } catch (e) { console.error('Twitch OAuth start:', e.message); return res.status(500).json({ error: 'Não foi possível iniciar a conexão Twitch.' }); }
});

app.get('/auth/twitch/callback', async (req, res) => {
  const cfg = getTwitchConfig();
  const clear = () => res.clearCookie('twitch_oauth_state', { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth/twitch/callback' });
  if (!supabase || !cfg || !getEncryptionKey()) { clear(); return res.status(503).send(resultPage('Configuração incompleta', 'A integração Twitch ainda não está configurada no servidor.')); }
  const a = verifySignedState(cfg.stateSecret, req.cookies.twitch_oauth_state);
  const b = verifySignedState(cfg.stateSecret, req.query.state);
  if (!a || !b || a.userId !== b.userId || a.nonce !== b.nonce || a.createdAt !== b.createdAt) { clear(); return res.status(400).send(resultPage('Solicitação inválida', 'Volte ao Suprema Studio e tente conectar novamente.')); }
  clear();
  if (req.query.error || typeof req.query.code !== 'string') return res.status(400).send(resultPage('Conexão cancelada', 'A autorização Twitch foi cancelada ou recusada.'));
  try {
    const tokenResponse = await fetch('https://id.twitch.tv/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, code: req.query.code, grant_type: 'authorization_code', redirect_uri: cfg.redirectUri }) });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token) { console.error('Twitch token exchange failed:', tokenResponse.status, tokens.message || tokens.message); return res.status(502).send(resultPage('Falha na autorização', 'A Twitch não concluiu a troca do código. Confira as credenciais e a URL de retorno.')); }
    const profileResponse = await fetch('https://api.twitch.tv/helix/users', { headers: { 'Client-Id': cfg.clientId, Authorization: `Bearer ${tokens.access_token}` } });
    const profileData = await profileResponse.json(); const profile = profileData.data?.[0];
    if (!profileResponse.ok || !profile?.id) return res.status(502).send(resultPage('Perfil não consultado', 'A autorização foi recebida, mas não foi possível consultar o perfil Twitch.'));
    const { data: account, error: accountError } = await supabase.from('social_accounts').upsert({ user_id: a.userId, platform: 'twitch', external_id: profile.id, display_name: profile.display_name || profile.login, scopes: Array.isArray(tokens.scope) ? tokens.scope : ['user:read:email'], status: 'connected', last_sync_at: new Date().toISOString() }, { onConflict: 'user_id,platform,external_id' }).select('id').single();
    if (accountError || !account?.id) throw accountError || new Error('Conta não retornada pelo banco.');
    const { error: tokenError } = await supabase.from('social_tokens').upsert({ account_id: account.id, access_token_enc: encryptToken(tokens.access_token), refresh_token_enc: tokens.refresh_token ? encryptToken(tokens.refresh_token) : null, expires_at: new Date(Date.now() + (Number(tokens.expires_in) || 3600) * 1000).toISOString() }, { onConflict: 'account_id' });
    if (tokenError) throw tokenError;
    return res.status(200).send(resultPage('Twitch conectada!', `A conta ${profile.display_name || profile.login} foi vinculada ao Suprema Studio. O token foi armazenado criptografado.`));
  } catch (e) { console.error('Twitch OAuth callback:', e.message); return res.status(500).send(resultPage('Erro na conexão', 'Ocorreu um erro ao salvar a conta Twitch. Tente novamente.')); }
});

app.post('/auth/twitch/disconnect', async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) return res.status(401).json({ error: 'Sessão inválida.' });
    const { data: account, error } = await supabase.from('social_accounts').select('id, external_id').eq('user_id', user.id).eq('platform', 'twitch').maybeSingle();
    if (error) throw error;
    if (!account) return res.json({ disconnected: true });
    const { data: tokenRow } = await supabase.from('social_tokens').select('access_token_enc').eq('account_id', account.id).maybeSingle();
    if (tokenRow?.access_token_enc) { try { const token = decryptToken(tokenRow.access_token_enc); await fetch('https://id.twitch.tv/oauth2/revoke', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: getTwitchConfig()?.clientId || '', token }) }); } catch (_) {} }
    const { error: deleteError } = await supabase.from('social_accounts').delete().eq('id', account.id).eq('user_id', user.id);
    if (deleteError) throw deleteError;
    return res.json({ disconnected: true });
  } catch (e) { console.error('Twitch disconnect:', e.message); return res.status(e.status || 500).json({ error: 'Não foi possível desconectar a Twitch.' }); }
});

app.get('/twitch-studio', (req, res) => res.sendFile(path.join(__dirname, 'public', 'twitch-studio.html')));

// --------------------------------------------------
// INICIALIZAÇÃO
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor iniciado na porta ${PORT}`);
});
