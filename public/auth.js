
(function () {
  const config = window.SUPREMA_CONFIG;

  if (
    !config ||
    !config.supabaseUrl ||
    !config.supabasePublishableKey
  ) {
    console.error("Configuração do Supabase não encontrada.");
    return;
  }

  if (!window.supabase) {
    console.error("Biblioteca do Supabase não carregada.");
    return;
  }

  const client = window.supabase.createClient(
    config.supabaseUrl,
    config.supabasePublishableKey
  );

  window.SUPREMA_AUTH = {
    async signUp(email, password) {
      return await client.auth.signUp({
        email,
        password
      });
    },

    async signIn(email, password) {
      return await client.auth.signInWithPassword({
        email,
        password
      });
    },

    async signOut() {
      return await client.auth.signOut();
    },

    async getSession() {
      return await client.auth.getSession();
    },

    onAuthStateChange(callback) {
      return client.auth.onAuthStateChange(callback);
    }
  };

  console.log("Suprema Auth inicializado.");
})();
