
const express = require("express");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

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

// Rota principal
app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    message: "Servidor funcionando!"
  });
});

// Verifica se as variáveis do Supabase estão configuradas
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "online",
    supabaseConfigured: supabase !== null
  });
});

// Testa uma consulta real ao banco de dados
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
      console.error(
        "Falha no teste do Supabase:",
        error.message
      );

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
    console.error(
      "Erro ao testar o Supabase:",
      error.message
    );

    return res.status(503).json({
      status: "error",
      databaseConnected: false
    });
  }
});

// Inicialização do servidor
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor iniciado na porta ${PORT}`);
});
