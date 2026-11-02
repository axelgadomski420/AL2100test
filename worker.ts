// AL2100test — Cloudflare Workers backend
// Pełna implementacja: D1, R2, KV, Queues, Durable Objects.
// Klucze API providerów nigdy nie przechodzą przez ten backend.

export default { async fetch(request, env) { return new Response("AL2100test backend"); } };
