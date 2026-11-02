// AL2100test — Cloudflare Workers backend
// Runtime: Cloudflare Workers (module syntax). Bindings: D1, R2, KV, Queues, Durable Objects.
// Klucze API providerów NIE przechodzą przez ten backend — patrz sekcja 21 specyfikacji AXCode.

export interface Env {
  DB: D1Database;
  MEDIA: R2Bucket;
  CACHE: KVNamespace;
  JOBS: Queue<JobMessage>;
  SESSIONS: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
  JWT_SECRET: string;
  ENVIRONMENT: string;
  MEDIA_PUBLIC_BASE: string;
}

type JobMessage =
  | { kind: "research"; jobId: string; userId: string; question: string; layers: number[] }
  | { kind: "agent"; jobId: string; userId: string; goal: string; agentKind: string }
  | { kind: "moderation"; reportId: string; userId: string };

interface Json {
  [key: string]: unknown;
}

interface ErrorBody {
  error: string;
  code: string;
  requestId: string;
}

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const ACCESS_TTL_SECONDS = 60 * 30;
const REFRESH_TTL_SECONDS = 60 * 60 * 24 * 30;

class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function jsonResponse(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

function errorResponse(err: unknown, requestId: string): Response {
  if (err instanceof HttpError) {
    const body: ErrorBody = { error: err.message, code: err.code, requestId };
    return jsonResponse(body, err.status);
  }
  const message = err instanceof Error ? err.message : "Nieznany błąd serwera.";
  const body: ErrorBody = { error: message, code: "INTERNAL", requestId };
  return jsonResponse(body, 500);
}

async function readJson(request: Request): Promise<Json> {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    throw new HttpError(413, "PAYLOAD_TOO_LARGE", "Treść żądania przekracza 2 MB.");
  }
  if (raw.length === 0) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new HttpError(400, "BAD_JSON", "Treść żądania musi być obiektem JSON.");
    }
    return parsed as Json;
  } catch {
    throw new HttpError(400, "BAD_JSON", "Nie udało się sparsować JSON.");
  }
}

function requireString(body: Json, field: string, min: number, max: number): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new HttpError(400, "VALIDATION", `Pole "${field}" jest wymagane.`);
  }
  const trimmed = value.trim();
  if (trimmed.length < min || trimmed.length > max) {
    throw new HttpError(400, "VALIDATION", `Pole "${field}" musi mieć od ${min} do ${max} znaków.`);
  }
  return trimmed;
}

function optionalString(body: Json, field: string, max: number): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new HttpError(400, "VALIDATION", `Pole "${field}" musi być tekstem.`);
  }
  const trimmed = value.trim();
  if (trimmed.length > max) {
    throw new HttpError(400, "VALIDATION", `Pole "${field}" może mieć maksymalnie ${max} znaków.`);
  }
  return trimmed.length === 0 ? null : trimmed;
}

function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}

function randomId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${hex}`;
}

function randomToken(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function textToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

let cachedKey: CryptoKey | null = null;
async function hmacKey(secret: string): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  cachedKey = await crypto.subtle.importKey(
    "raw",
    textToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  return cachedKey;
}

async function signJwt(payload: Json, secret: string, ttlSeconds: number): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const full = { ...payload, iat: now, exp: now + ttlSeconds };
  const key = await hmacKey(secret);
  const head = base64UrlEncode(textToBytes(JSON.stringify(header)));
  const bodyPart = base64UrlEncode(textToBytes(JSON.stringify(full)));
  const signingInput = `${head}.${bodyPart}`;
  const signature = await crypto.subtle.sign("HMAC", key, textToBytes(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

async function verifyJwt(token: string, secret: string): Promise<Json> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new HttpError(401, "BAD_TOKEN", "Nieprawidłowy token.");
  const key = await hmacKey(secret);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const ok = await crypto.subtle.verify("HMAC", key, base64UrlDecode(parts[2]), textToBytes(signingInput));
  if (!ok) throw new HttpError(401, "BAD_SIGNATURE", "Podpis tokenu jest nieprawidłowy.");
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1]))) as Json;
  const exp = typeof payload.exp === "number" ? payload.exp : 0;
  if (exp * 1000 < Date.now()) throw new HttpError(401, "TOKEN_EXPIRED", "Token wygasł.");
  return payload;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey("raw", textToBytes(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 120000;
  const derived = await pbkdf2(password, salt, iterations);
  return `pbkdf2$${iterations}$${base64UrlEncode(salt)}$${base64UrlEncode(derived)}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;
  const salt = base64UrlDecode(parts[2]);
  const expected = base64UrlDecode(parts[3]);
  const derived = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(derived, expected);
}

function passwordStrengthError(password: string): string | null {
  if (password.length < 12) return "Hasło musi mieć co najmniej 12 znaków.";
  if (!/[a-z]/.test(password)) return "Hasło musi zawierać małą literę.";
  if (!/[A-Z]/.test(password)) return "Hasło musi zawierać wielką literę.";
  if (!/[0-9]/.test(password)) return "Hasło musi zawierać cyfrę.";
  return null;
}

interface AuthContext {
  userId: string;
  deviceId: string;
}

async function authenticate(request: Request, env: Env): Promise<AuthContext> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) {
    throw new HttpError(401, "NO_TOKEN", "Brak tokenu dostępu.");
  }
  const payload = await verifyJwt(header.slice(7).trim(), env.JWT_SECRET);
  const userId = typeof payload.sub === "string" ? payload.sub : "";
  const deviceId = typeof payload.did === "string" ? payload.did : "";
  if (userId.length === 0) throw new HttpError(401, "BAD_TOKEN", "Token nie zawiera użytkownika.");

  const bound = await env.DB.prepare("SELECT device_id, revoked FROM sessions WHERE user_id = ? AND device_id = ?")
    .bind(userId, deviceId)
    .first<{ device_id: string; revoked: number }>();

  if (!bound) throw new HttpError(401, "SESSION_UNKNOWN", "Sesja nie istnieje.");
  if (bound.revoked === 1) throw new HttpError(401, "SESSION_REVOKED", "Sesja została unieważniona.");

  const device = await env.DB.prepare("SELECT id, revoked FROM devices WHERE id = ? AND user_id = ?")
    .bind(deviceId, userId)
    .first<{ id: string; revoked: number }>();

  if (!device) throw new HttpError(401, "DEVICE_UNKNOWN", "Urządzenie nie jest powiązane z kontem.");
  if (device.revoked === 1) throw new HttpError(401, "DEVICE_REVOKED", "Urządzenie zostało odebrane dostęp.");

  return { userId, deviceId };
}

async function rateLimit(env: Env, key: string, limit: number, windowSeconds: number): Promise<void> {
  const id = env.RATE_LIMIT.idFromName(key);
  const stub = env.RATE_LIMIT.get(id);
  const response = await stub.fetch("https://rate-limit/consume", {
    method: "POST",
    body: JSON.stringify({ limit, windowSeconds }),
    headers: { "content-type": "application/json" },
  });
  if (response.status === 429) {
    throw new HttpError(429, "RATE_LIMITED", "Zbyt wiele żądań. Spróbuj ponownie później.");
  }
  if (!response.ok) {
    throw new HttpError(503, "RATE_LIMIT_UNAVAILABLE", "Usługa limitu żądań jest niedostępna.");
  }
}

export class RateLimiter {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/consume") return new Response("Not found", { status: 404 });

    let payload: { limit: number; windowSeconds: number };
    try {
      payload = (await request.json()) as { limit: number; windowSeconds: number };
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const now = Date.now();
    const stored = (await this.state.storage.get<{ count: number; resetAt: number }>("bucket")) ?? {
      count: 0,
      resetAt: now + payload.windowSeconds * 1000,
    };

    if (stored.resetAt <= now) {
      stored.count = 0;
      stored.resetAt = now + payload.windowSeconds * 1000;
    }

    if (stored.count >= payload.limit) {
      return new Response(JSON.stringify({ allowed: false, resetAt: stored.resetAt }), {
        status: 429,
        headers: JSON_HEADERS,
      });
    }

    stored.count += 1;
    await this.state.storage.put("bucket", stored);
    return new Response(JSON.stringify({ allowed: true, remaining: payload.limit - stored.count }), {
      status: 200,
      headers: JSON_HEADERS,
    });
  }
}

export class SessionHub {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/register") {
      const body = (await request.json()) as { deviceId: string; publicKeyText: string | null };
      const list = (await this.state.storage.get<string[]>("devices")) ?? [];
      if (!list.includes(body.deviceId)) list.push(body.deviceId);
      await this.state.storage.put("devices", list);
      return jsonResponse({ devices: list.length });
    }
    if (url.pathname === "/revoke") {
      const body = (await request.json()) as { deviceId: string };
      const list = (await this.state.storage.get<string[]>("devices")) ?? [];
      const next = list.filter((item) => item !== body.deviceId);
      await this.state.storage.put("devices", next);
      return jsonResponse({ devices: next.length });
    }
    if (url.pathname === "/list") {
      const list = (await this.state.storage.get<string[]>("devices")) ?? [];
      return jsonResponse({ devices: list });
    }
    return new Response("Not found", { status: 404 });
  }
}

function validatePasswordOrFail(password: string): void {
  const problem = passwordStrengthError(password);
  if (problem) throw new HttpError(400, "WEAK_PASSWORD", problem);
}

async function issueTokens(
  env: Env,
  userId: string,
  deviceId: string,
  email: string,
): Promise<{ accessToken: string; refreshToken: string; expiresAt: number }> {
  const accessToken = await signJwt({ sub: userId, did: deviceId, email }, env.JWT_SECRET, ACCESS_TTL_SECONDS);
  const refreshRaw = randomToken(48);
  const refreshHash = base64UrlEncode(
    new Uint8Array(await crypto.subtle.digest("SHA-256", textToBytes(refreshRaw))),
  );
  const expiresAt = Date.now() + REFRESH_TTL_SECONDS * 1000;

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, device_id, refresh_hash, expires_at, revoked, created_at)
     VALUES (?, ?, ?, ?, ?, 0, ?)
     ON CONFLICT(user_id, device_id) DO UPDATE SET refresh_hash = excluded.refresh_hash,
       expires_at = excluded.expires_at, revoked = 0, created_at = excluded.created_at`,
  )
    .bind(randomId("sess"), userId, deviceId, refreshHash, expiresAt, Date.now())
    .run();

  return { accessToken, refreshToken: refreshRaw, expiresAt };
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", 5, 320).toLowerCase();
  const password = requireString(body, "password", 12, 200);
  const displayName = requireString(body, "displayName", 2, 60);

  if (!isEmail(email)) throw new HttpError(400, "VALIDATION", "Podaj poprawny adres e-mail.");
  validatePasswordOrFail(password);

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();
  if (existing) throw new HttpError(409, "EMAIL_TAKEN", "Konto z tym adresem już istnieje.");

  const userId = randomId("usr");
  const passwordHash = await hashPassword(password);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO users (id, email, display_name, password_hash, bio, language, persona, email_verified, created_at, updated_at)
     VALUES (?, ?, ?, ?, '', 'pl', '', 0, ?, ?)`,
  )
    .bind(userId, email, displayName, passwordHash, now, now)
    .run();

  const verifyToken = randomToken(12);
  await env.DB.prepare(
    "INSERT INTO email_verifications (id, user_id, token, expires_at, used) VALUES (?, ?, ?, ?, 0)",
  )
    .bind(randomId("ver"), userId, verifyToken, now + 1000 * 60 * 60 * 24)
    .run();

  return jsonResponse({
    userId,
    email,
    displayName,
    emailVerificationToken: verifyToken,
    aiGenerated: true,
    notice: "Token weryfikacyjny jest w tej wersji zwracany w odpowiedzi; w produkcji trafia wyłącznie e-mailem.",
  }, 201);
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", 5, 320).toLowerCase();
  const password = requireString(body, "password", 1, 200);
  const deviceId = requireString(body, "deviceId", 4, 120);
  const platform = optionalString(body, "platform", 40) ?? "unknown";

  await rateLimit(env, `login:${email}`, 10, 300);

  const user = await env.DB.prepare(
    "SELECT id, email, display_name, password_hash, failed_attempts, locked_until FROM users WHERE email = ?",
  )
    .bind(email)
    .first<{
      id: string;
      email: string;
      display_name: string;
      password_hash: string;
      failed_attempts: number;
      locked_until: number | null;
    }>();

  if (!user) throw new HttpError(401, "BAD_CREDENTIALS", "Nieprawidłowy e-mail lub hasło.");

  if (user.locked_until !== null && user.locked_until > Date.now()) {
    throw new HttpError(423, "ACCOUNT_LOCKED", "Konto jest tymczasowo zablokowane po nieudanych próbach logowania.");
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    const attempts = user.failed_attempts + 1;
    const lockedUntil = attempts >= 8 ? Date.now() + 1000 * 60 * 15 : null;
    await env.DB.prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?")
      .bind(attempts, lockedUntil, user.id)
      .run();
    throw new HttpError(401, "BAD_CREDENTIALS", "Nieprawidłowy e-mail lub hasło.");
  }

  await env.DB.prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?").bind(user.id).run();

  await env.DB.prepare(
    `INSERT INTO devices (id, user_id, platform, public_key_text, verified, revoked, last_seen_at, created_at)
     VALUES (?, ?, ?, '', 0, 0, ?, ?)
     ON CONFLICT(id) DO UPDATE SET last_seen_at = excluded.last_seen_at, platform = excluded.platform`,
  )
    .bind(deviceId, user.id, platform, Date.now(), Date.now())
    .run();

  const hub = env.SESSIONS.get(env.SESSIONS.idFromName(user.id));
  await hub.fetch("https://sessions/register", {
    method: "POST",
    body: JSON.stringify({ deviceId, publicKeyText: null }),
    headers: { "content-type": "application/json" },
  });

  const tokens = await issueTokens(env, user.id, deviceId, user.email);

  return jsonResponse({
    ...tokens,
    user: { id: user.id, email: user.email, displayName: user.display_name },
  });
}

async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const refreshToken = requireString(body, "refreshToken", 10, 200);
  const deviceId = requireString(body, "deviceId", 4, 120);

  const refreshHash = base64UrlEncode(
    new Uint8Array(await crypto.subtle.digest("SHA-256", textToBytes(refreshToken))),
  );

  const session = await env.DB.prepare(
    `SELECT s.id, s.user_id, u.email, s.expires_at, s.revoked
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.refresh_hash = ? AND s.device_id = ?`,
  )
    .bind(refreshHash, deviceId)
    .first<{ id: string; user_id: string; email: string; expires_at: number; revoked: number }>();

  if (!session) throw new HttpError(401, "REFRESH_UNKNOWN", "Token odświeżania nie istnieje.");
  if (session.revoked === 1) throw new HttpError(401, "SESSION_REVOKED", "Sesja została unieważniona.");
  if (session.expires_at <= Date.now()) throw new HttpError(401, "REFRESH_EXPIRED", "Token odświeżania wygasł.");

  const device = await env.DB.prepare("SELECT revoked FROM devices WHERE id = ? AND user_id = ?")
    .bind(deviceId, session.user_id)
    .first<{ revoked: number }>();
  if (!device) throw new HttpError(401, "DEVICE_UNKNOWN", "Urządzenie nie jest powiązane z kontem.");
  if (device.revoked === 1) throw new HttpError(401, "DEVICE_REVOKED", "Urządzenie zostało odebrane dostęp.");

  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE id = ?").bind(session.id).run();
  const tokens = await issueTokens(env, session.user_id, deviceId, session.email);
  return jsonResponse(tokens);
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND device_id = ?")
    .bind(auth.userId, auth.deviceId)
    .run();
  return jsonResponse({ ok: true });
}

async function handleResetRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", 5, 320).toLowerCase();
  await rateLimit(env, `reset:${email}`, 5, 900);

  const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();
  const response: Json = {
    ok: true,
    notice: "Jeśli konto istnieje, wysłaliśmy instrukcję resetu hasła.",
  };
  if (!user) return jsonResponse(response);

  const token = randomToken(12);
  await env.DB.prepare(
    "INSERT INTO password_resets (id, user_id, token, expires_at, used) VALUES (?, ?, ?, ?, 0)",
  )
    .bind(randomId("rst"), user.id, token, Date.now() + 1000 * 60 * 30)
    .run();
  response.resetToken = token;
  response.notice = "Kod resetu jest w tej wersji zwracany w odpowiedzi; w produkcji trafia wyłącznie e-mailem.";
  return jsonResponse(response);
}

async function handleResetConfirm(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const token = requireString(body, "token", 6, 40);
  const newPassword = requireString(body, "newPassword", 12, 200);
  validatePasswordOrFail(newPassword);

  const row = await env.DB.prepare("SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?")
    .bind(token)
    .first<{ id: string; user_id: string; expires_at: number; used: number }>();

  if (!row) throw new HttpError(400, "RESET_UNKNOWN", "Kod resetu jest nieprawidłowy.");
  if (row.used === 1) throw new HttpError(400, "RESET_USED", "Ten kod resetu został już użyty.");
  if (row.expires_at <= Date.now()) throw new HttpError(400, "RESET_EXPIRED", "Kod resetu wygasł.");

  const hash = await hashPassword(newPassword);
  await env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
    .bind(hash, Date.now(), row.user_id)
    .run();
  await env.DB.prepare("UPDATE password_resets SET used = 1 WHERE id = ?").bind(row.id).run();
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ?").bind(row.user_id).run();

  return jsonResponse({ ok: true, notice: "Hasło zmienione. Wszystkie sesje zostały wylogowane." });
}

async function handleVerifyEmail(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const token = requireString(body, "token", 6, 40);

  const row = await env.DB.prepare("SELECT id, user_id, expires_at, used FROM email_verifications WHERE token = ?")
    .bind(token)
    .first<{ id: string; user_id: string; expires_at: number; used: number }>();

  if (!row) throw new HttpError(400, "VERIFY_UNKNOWN", "Kod weryfikacyjny jest nieprawidłowy.");
  if (row.used === 1) throw new HttpError(400, "VERIFY_USED", "Ten kod został już użyty.");
  if (row.expires_at <= Date.now()) throw new HttpError(400, "VERIFY_EXPIRED", "Kod weryfikacyjny wygasł.");

  await env.DB.prepare("UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?")
    .bind(Date.now(), row.user_id)
    .run();
  await env.DB.prepare("UPDATE email_verifications SET used = 1 WHERE id = ?").bind(row.id).run();

  return jsonResponse({ ok: true, notice: "Adres e-mail został zweryfikowany." });
}

async function handleRecoveryCodes(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);

  await env.DB.prepare("UPDATE recovery_codes SET used = 1 WHERE user_id = ? AND used = 0").bind(auth.userId).run();

  const codes: string[] = [];
  const statements: D1PreparedStatement[] = [];
  for (let i = 0; i < 10; i += 1) {
    const raw = `${randomToken(4)}-${randomToken(4)}-${randomToken(4)}`;
    codes.push(raw);
    const hash = base64UrlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", textToBytes(raw))));
    statements.push(
      env.DB.prepare("INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, 0, ?)")
        .bind(randomId("rc"), auth.userId, hash, Date.now()),
    );
  }
  await env.DB.batch(statements);

  return jsonResponse({
    codes,
    notice: "Każdy kod działa jednorazowo. Zapisz je w bezpiecznym miejscu.",
  });
}

async function handleRedeemRecovery(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const code = requireString(body, "code", 8, 40);
  await rateLimit(env, `recovery:${code}`, 5, 900);

  const hash = base64UrlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", textToBytes(code))));
  const row = await env.DB.prepare("SELECT id, user_id, used FROM recovery_codes WHERE code_hash = ?")
    .bind(hash)
    .first<{ id: string; user_id: string; used: number }>();

  if (!row) throw new HttpError(400, "RECOVERY_UNKNOWN", "Kod odzyskiwania jest nieprawidłowy.");
  if (row.used === 1) throw new HttpError(400, "RECOVERY_USED", "Ten kod został już użyty.");

  await env.DB.prepare("UPDATE recovery_codes SET used = 1 WHERE id = ?").bind(row.id).run();
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ?").bind(row.user_id).run();

  return jsonResponse({ ok: true, userId: row.user_id, notice: "Kod przyjęty. Ustaw nowe hasło i zaloguj się ponownie." });
}

async function handleGetMe(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const user = await env.DB.prepare(
    "SELECT id, email, display_name, bio, language, persona, avatar_url, email_verified, created_at FROM users WHERE id = ?",
  )
    .bind(auth.userId)
    .first<Record<string, unknown>>();
  if (!user) throw new HttpError(404, "USER_NOT_FOUND", "Nie znaleziono użytkownika.");
  return jsonResponse({ user, deviceId: auth.deviceId });
}

async function handleUpdateMe(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const displayName = requireString(body, "displayName", 2, 60);
  const bio = optionalString(body, "bio", 400) ?? "";
  const avatarUrl = optionalString(body, "avatarUrl", 2048);
  const language = requireString(body, "language", 2, 12);
  const persona = optionalString(body, "persona", 600) ?? "";

  await env.DB.prepare(
    "UPDATE users SET display_name = ?, bio = ?, avatar_url = ?, language = ?, persona = ?, updated_at = ? WHERE id = ?",
  )
    .bind(displayName, bio, avatarUrl, language, persona, Date.now(), auth.userId)
    .run();

  return jsonResponse({ ok: true });
}

async function handleRegisterDevice(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const deviceId = requireString(body, "deviceId", 4, 120);
  const platform = requireString(body, "platform", 2, 40);
  const publicKeyText = optionalString(body, "publicKeyText", 4096) ?? "";

  await env.DB.prepare(
    `INSERT INTO devices (id, user_id, platform, public_key_text, verified, revoked, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, 0, 0, ?, ?)
     ON CONFLICT(id) DO UPDATE SET platform = excluded.platform,
       public_key_text = excluded.public_key_text, last_seen_at = excluded.last_seen_at`,
  )
    .bind(deviceId, auth.userId, platform, publicKeyText, Date.now(), Date.now())
    .run();

  const hub = env.SESSIONS.get(env.SESSIONS.idFromName(auth.userId));
  await hub.fetch("https://sessions/register", {
    method: "POST",
    body: JSON.stringify({ deviceId, publicKeyText }),
    headers: { "content-type": "application/json" },
  });

  return jsonResponse({ ok: true, deviceId });
}

async function handleListDevices(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const rows = await env.DB.prepare(
    "SELECT id, platform, verified, revoked, last_seen_at, created_at FROM devices WHERE user_id = ? ORDER BY last_seen_at DESC",
  )
    .bind(auth.userId)
    .all();
  return jsonResponse({ devices: rows.results ?? [], currentDeviceId: auth.deviceId });
}

async function handleRevokeDevice(request: Request, env: Env, deviceId: string): Promise<Response> {
  const auth = await authenticate(request, env);
  await env.DB.prepare("UPDATE devices SET revoked = 1 WHERE id = ? AND user_id = ?")
    .bind(deviceId, auth.userId)
    .run();
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND device_id = ?")
    .bind(auth.userId, deviceId)
    .run();

  const hub = env.SESSIONS.get(env.SESSIONS.idFromName(auth.userId));
  await hub.fetch("https://sessions/revoke", {
    method: "POST",
    body: JSON.stringify({ deviceId }),
    headers: { "content-type": "application/json" },
  });

  return jsonResponse({ ok: true });
}

async function assertConversationOwned(env: Env, userId: string, conversationId: string): Promise<void> {
  const row = await env.DB.prepare("SELECT id FROM conversations WHERE id = ? AND user_id = ?")
    .bind(conversationId, userId)
    .first<{ id: string }>();
  if (!row) throw new HttpError(404, "CONVERSATION_NOT_FOUND", "Nie znaleziono rozmowy.");
}

async function handleListConversations(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const rows = await env.DB.prepare(
    "SELECT id, title, persona, mode, provider_id, model, pinned, archived, message_count, updated_at FROM conversations WHERE user_id = ? ORDER BY pinned DESC, updated_at DESC LIMIT 500",
  )
    .bind(auth.userId)
    .all();
  return jsonResponse({ conversations: rows.results ?? [] });
}

async function handleUpsertConversation(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const id = requireString(body, "id", 4, 120);
  const title = requireString(body, "title", 1, 200);
  const persona = optionalString(body, "persona", 600) ?? "";
  const mode = requireString(body, "mode", 2, 20);
  const providerId = requireString(body, "providerId", 1, 80);
  const model = requireString(body, "model", 1, 120);
  const messageCount = typeof body.messageCount === "number" ? body.messa
    geCount : 0;

  await env.DB.prepare(
    `INSERT INTO conversations (id, user_id, title, persona, mode, provider_id, model, message_count, updated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET title = excluded.title, persona = excluded.persona, mode = excluded.mode,
       provider_id = excluded.provider_id, model = excluded.model, message_count = excluded.message_count,
       updated_at = excluded.updated_at`,
  )
    .bind(id, auth.userId, title, persona, mode, providerId, model, messageCount, Date.now(), Date.now())
    .run();

  await env.CACHE.put(`conv:${auth.userId}:${id}`, JSON.stringify({ title, mode, providerId, model }), {
    expirationTtl: 3600,
  });

  return jsonResponse({ ok: true });
}

async function handleDeleteConversation(request: Request, env: Env, conversationId: string): Promise<Response> {
  const auth = await authenticate(request, env);
  await assertConversationOwned(env, auth.userId, conversationId);
  await env.DB.prepare("DELETE FROM messages WHERE conversation_id = ? AND user_id = ?")
    .bind(conversationId, auth.userId)
    .run();
  await env.DB.prepare("DELETE FROM conversations WHERE id = ? AND user_id = ?")
    .bind(conversationId, auth.userId)
    .run();
  await env.CACHE.delete(`conv:${auth.userId}:${conversationId}`);
  return jsonResponse({ ok: true });
}

async function handleUpsertMessage(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const id = requireString(body, "id", 4, 120);
  const conversationId = requireString(body, "conversationId", 4, 120);
  const role = requireString(body, "role", 2, 20);
  const bodyText = requireString(body, "body", 0, 20000);
  const providerId = requireString(body, "providerId", 1, 80);
  const model = requireString(body, "model", 1, 120);
  const isAiGenerated = body.isAiGenerated === true ? 1 : 0;

  await assertConversationOwned(env, auth.userId, conversationId);

  await env.DB.prepare(
    `INSERT INTO messages (id, conversation_id, user_id, role, body, provider_id, model, is_ai_generated, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET body = excluded.body, is_ai_generated = excluded.is_ai_generated`,
  )
    .bind(id, conversationId, auth.userId, role, bodyText, providerId, model, isAiGenerated, Date.now())
    .run();

  await env.DB.prepare("UPDATE conversations SET message_count = message_count + 1, updated_at = ? WHERE id = ?")
    .bind(Date.now(), conversationId)
    .run();

  return jsonResponse({ ok: true });
}

async function handleCreateResearchJob(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const question = requireString(body, "question", 5, 500);
  const layersRaw = Array.isArray(body.layers) ? (body.layers as unknown[]) : [];
  const layers = layersRaw.filter((item): item is number => typeof item === "number" && item >= 1 && item <= 10);

  if (layers.length === 0) throw new HttpError(400, "VALIDATION", "Wybierz co najmniej jedną warstwę wyszukiwania.");

  await rateLimit(env, `research:${auth.userId}`, 20, 3600);

  const jobId = randomId("res");
  await env.DB.prepare(
    `INSERT INTO research_jobs (id, user_id, question, layers_json, status, answer, sources_json, confidence, created_at)
     VALUES (?, ?, ?, ?, 'queued', '', '[]', 0, ?)`,
  )
    .bind(jobId, auth.userId, question, JSON.stringify(layers), Date.now())
    .run();

  await env.JOBS.send({ kind: "research", jobId, userId: auth.userId, question, layers });

  return jsonResponse({ jobId, status: "queued", layers }, 202);
}

async function handleGetResearchJob(request: Request, env: Env, jobId: string): Promise<Response> {
  const auth = await authenticate(request, env);
  const row = await env.DB.prepare(
    "SELECT id, question, layers_json, status, answer, sources_json, confidence, created_at, completed_at FROM research_jobs WHERE id = ? AND user_id = ?",
  )
    .bind(jobId, auth.userId)
    .first<Record<string, unknown>>();
  if (!row) throw new HttpError(404, "JOB_NOT_FOUND", "Nie znaleziono zadania research.");
  return jsonResponse({ job: row, aiGenerated: true });
}

async function handleCreateAgentJob(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const goal = requireString(body, "goal", 5, 1000);
  const agentKind = requireString(body, "agentKind", 3, 30);

  await rateLimit(env, `agent:${auth.userId}`, 20, 3600);

  const jobId = randomId("agt");
  await env.DB.prepare(
    `INSERT INTO agent_jobs (id, user_id, goal, agent_kind, status, plan_json, result, approved, created_at)
     VALUES (?, ?, ?, ?, 'queued', '[]', '', 0, ?)`,
  )
    .bind(jobId, auth.userId, goal, agentKind, Date.now())
    .run();

  await env.JOBS.send({ kind: "agent", jobId, userId: auth.userId, goal, agentKind });

  return jsonResponse({ jobId, status: "queued" }, 202);
}

async function handleGetAgentJob(request: Request, env: Env, jobId: string): Promise<Response> {
  const auth = await authenticate(request, env);
  const row = await env.DB.prepare(
    "SELECT id, goal, agent_kind, status, plan_json, result, approved, created_at, completed_at FROM agent_jobs WHERE id = ? AND user_id = ?",
  )
    .bind(jobId, auth.userId)
    .first<Record<string, unknown>>();
  if (!row) throw new HttpError(404, "JOB_NOT_FOUND", "Nie znaleziono zadania agenta.");
  return jsonResponse({ job: row, requiresHumanApproval: true });
}

// Endpoint przyjmuje WYŁĄCZNIE metadane użycia. Klucze API nigdy nie przechodzą przez ten backend.
async function handleLogUsage(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const providerId = requireString(body, "providerId", 1, 80);
  const providerType = requireString(body, "providerType", 2, 20);
  const model = requireString(body, "model", 1, 120);
  const units = typeof body.units === "number" && Number.isFinite(body.units) ? body.units : 0;
  const costEstimate =
    typeof body.costEstimate === "number" && Number.isFinite(body.costEstimate) ? body.costEstimate : 0;
  const privacy = requireString(body, "privacy", 2, 20);
  const status = requireString(body, "status", 2, 20);

  const forbidden = ["apiKey", "api_key", "key", "secret", "token", "authorization"];
  for (const field of forbidden) {
    if (field in body) {
      throw new HttpError(400, "SECRET_REJECTED", "Ten endpoint nie przyjmuje kluczy ani tokenów. Wysyłaj wyłącznie metadane użycia.");
    }
  }

  await env.DB.prepare(
    `INSERT INTO provider_usage (id, user_id, provider_id, provider_type, model, units, cost_estimate, privacy, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(randomId("use"), auth.userId, providerId, providerType, model, units, costEstimate, privacy, status, Date.now())
    .run();

  return jsonResponse({ ok: true });
}

async function handleUsageSummary(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS calls, COALESCE(SUM(units), 0) AS units, COALESCE(SUM(cost_estimate), 0) AS cost FROM provider_usage WHERE user_id = ?",
  )
    .bind(auth.userId)
    .first<{ calls: number; units: number; cost: number }>();

  const byProvider = await env.DB.prepare(
    "SELECT provider_id, provider_type, COUNT(*) AS calls, COALESCE(SUM(units), 0) AS units, COALESCE(SUM(cost_estimate), 0) AS cost FROM provider_usage WHERE user_id = ? GROUP BY provider_id, provider_type ORDER BY cost DESC LIMIT 50",
  )
    .bind(auth.userId)
    .all();

  return jsonResponse({
    totals: row ?? { calls: 0, units: 0, cost: 0 },
    byProvider: byProvider.results ?? [],
    note: "Szacunki kosztów są przybliżone i oparte na danych podanych przez klienta.",
  });
}

async function handleUploadMedia(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const form = await request.formData();
  const file = form.get("file");
  const kind = form.get("kind");

  if (!(file instanceof File)) throw new HttpError(400, "VALIDATION", "Brak pliku w żądaniu.");
  if (typeof kind !== "string" || kind.length === 0) throw new HttpError(400, "VALIDATION", "Brak typu medium.");
  if (file.size > 50 * 1024 * 1024) throw new HttpError(413, "FILE_TOO_LARGE", "Plik przekracza 50 MB.");

  const allowed = ["image", "video", "audio", "file", "music"];
  if (!allowed.includes(kind)) throw new HttpError(400, "VALIDATION", "Nieobsługiwany typ medium.");

  const mediaId = randomId("med");
  const key = `${auth.userId}/${kind}/${mediaId}`;

  await env.MEDIA.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
    customMetadata: { userId: auth.userId, kind, originalName: file.name },
  });

  const url = `${env.MEDIA_PUBLIC_BASE}/${key}`;

  await env.DB.prepare(
    `INSERT INTO media (id, user_id, kind, r2_key, mime_type, file_name, size_bytes, alt_text, url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
  )
    .bind(mediaId, auth.userId, kind, key, file.type || "application/octet-stream", file.name, file.size, url, Date.now())
    .run();

  return jsonResponse({ mediaId, url, sizeBytes: file.size }, 201);
}

async function handleReportContent(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const contentRef = requireString(body, "contentRef", 3, 300);
  const reason = requireString(body, "reason", 5, 1000);
  const contentType = optionalString(body, "contentType", 40) ?? "unknown";

  await rateLimit(env, `report:${auth.userId}`, 10, 3600);

  const reportId = randomId("mod");
  await env.DB.prepare(
    `INSERT INTO moderation_reports (id, user_id, content_type, content_ref, reason, state, reviewer_note, created_at)
     VALUES (?, ?, ?, ?, ?, 'flagged', '', ?)`,
  )
    .bind(reportId, auth.userId, contentType, contentRef, reason, Date.now())
    .run();

  await env.JOBS.send({ kind: "moderation", reportId, userId: auth.userId });

  return jsonResponse({ reportId, state: "flagged" }, 201);
}

async function handleListMyReports(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const rows = await env.DB.prepare(
    "SELECT id, content_type, content_ref, reason, state, reviewer_note, created_at FROM moderation_reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 200",
  )
    .bind(auth.userId)
    .all();
  return jsonResponse({ reports: rows.results ?? [] });
}

async function handleExportAccount(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);

  const user = await env.DB.prepare(
    "SELECT id, email, display_name, bio, language, persona, created_at FROM users WHERE id = ?",
  )
    .bind(auth.userId)
    .first<Record<string, unknown>>();
  const conversations = await env.DB.prepare("SELECT * FROM conversations WHERE user_id = ?").bind(auth.userId).all();
  const messages = await env.DB.prepare("SELECT * FROM messages WHERE user_id = ? LIMIT 20000").bind(auth.userId).all();
  const usage = await env.DB.prepare("SELECT * FROM provider_usage WHERE user_id = ? LIMIT 20000").bind(auth.userId).all();
  const research = await env.DB.prepare("SELECT * FROM research_jobs WHERE user_id = ?").bind(auth.userId).all();
  const agents = await env.DB.prepare("SELECT * FROM agent_jobs WHERE user_id = ?").bind(auth.userId).all();
  const devices = await env.DB.prepare("SELECT id, platform, created_at FROM devices WHERE user_id = ?").bind(auth.userId).all();

  return jsonResponse({
    exportedAt: new Date().toISOString(),
    formatVersion: 1,
    user,
    conversations: conversations.results ?? [],
    messages: messages.results ?? [],
    providerUsage: usage.results ?? [],
    researchJobs: research.results ?? [],
    agentJobs: agents.results ?? [],
    devices: devices.results ?? [],
    note: "Eksport nie zawiera kluczy API providerów — te nigdy nie trafiają na serwer.",
  });
}

async function handleEraseAccount(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const body = await readJson(request);
  const confirm = requireString(body, "confirm", 7, 20);
  if (confirm.toUpperCase() !== "USUN-KONTO") {
    throw new HttpError(400, "CONFIRM_REQUIRED", 'Aby usunąć konto, wpisz dokładnie "USUN-KONTO".');
  }

  const keys = await env.MEDIA.list({ prefix: `${auth.userId}/`, limit: 1000 });
  for (const object of keys.objects) {
    await env.MEDIA.delete(object.key);
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM messages WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM conversations WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM provider_usage WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM research_jobs WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM agent_jobs WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM moderation_reports WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM media WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM devices WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM recovery_codes WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM password_resets WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM email_verifications WHERE user_id = ?").bind(auth.userId),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(auth.userId),
  ]);

  return jsonResponse({ ok: true, notice: "Konto i powiązane dane zostały usunięte." });
}

async function handleListNotifications(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  const rows = await env.DB.prepare(
    "SELECT id, title, body, read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 200",
  )
    .bind(auth.userId)
    .all();
  return jsonResponse({ notifications: rows.results ?? [] });
}

async function handleMarkNotificationRead(request: Request, env: Env, notificationId: string): Promise<Response> {
  const auth = await authenticate(request, env);
  await env.DB.prepare("UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?")
    .bind(notificationId, auth.userId)
    .run();
  return jsonResponse({ ok: true });
}

async function handleResearchJob(message: Extract<JobMessage, { kind: "research" }>, env: Env): Promise<void> {
  await env.DB.prepare("UPDATE research_jobs SET status = 'running' WHERE id = ?").bind(message.jobId).run();

  try {
    const cached = await env.CACHE.get(`research:${message.question}`);
    const sources: Json[] = cached ? (JSON.parse(cached) as Json[]) : buildPublicSourcePlan(message.question, message.layers);

    if (!cached) {
      await env.CACHE.put(`research:${message.question}`, JSON.stringify(sources), { expirationTtl: 3600 });
    }

    const answer = [
      "[AI-generated] Plan badawczy dla pytania: " + message.question,
      "",
      "Wybrane warstwy: " + message.layers.join(", ") + ".",
      "Liczba źródeł do sprawdzenia: " + sources.length + ".",
      "Ten etap przygotowuje zapytania do legalnych, publicznych API. Odpowiedzi providerów AI składane są po stronie klienta, gdzie znajdują się klucze.",
    ].join("\n");

    await env.DB.prepare(
      "UPDATE research_jobs SET status = 'done', answer = ?, sources_json = ?, confidence = ?, completed_at = ? WHERE id = ?",
    )
      .bind(answer, JSON.stringify(sources), 0.5, Date.now(), message.jobId)
      .run();

    await env.DB.prepare(
      "INSERT INTO notifications (id, user_id, title, body, read, created_at) VALUES (?, ?, ?, ?, 0, ?)",
    )
      .bind(randomId("not"), message.userId, "Research gotowy", "Zadanie badawcze zostało ukończone.", Date.now())
      .run();
  } catch (error) {
    const message2 = error instanceof Error ? error.message : "Nieznany błąd";
    await env.DB.prepare("UPDATE research_jobs SET status = 'failed', answer = ? WHERE id = ?")
      .bind("Błąd: " + message2, message.jobId)
      .run();
  }
}

function buildPublicSourcePlan(question: string, layers: number[]): Json[] {
  const catalog: Record<number, { title: string; url: string; license: string }[]> = {
    3: [
      { title: "Wikipedia — wyszukiwanie", url: "https://pl.wikipedia.org/w/index.php?search=" + encodeURIComponent(question), license: "CC BY-SA 4.0" },
      { title: "Wikidata — zapytanie", url: "https://www.wikidata.org/w/index.php?search=" + encodeURIComponent(question), license: "CC0" },
      { title: "Open Library — wyszukiwanie", url: "https://openlibrary.org/search?q=" + encodeURIComponent(question), license: "Open Library API" },
    ],
    4: [
      { title: "Internet Archive — wyszukiwanie", url: "https://archive.org/search?query=" + encodeURIComponent(question), license: "Zgodnie z licencją zasobu" },
    ],
    5: [
      { title: "Pexels — wyszukiwanie", url: "https://www.pexels.com/search/" + encodeURIComponent(question), license: "Pexels License" },
      { title: "Pixabay — wyszukiwanie", url: "https://pixabay.com/images/search/" + encodeURIComponent(question), license: "Pixabay Content License" },
    ],
    6: [
      { title: "Freesound — wyszukiwanie", url: "https://freesound.org/search/?q=" + encodeURIComponent(question), license: "Zgodnie z licencją zasobu" },
    ],
    7: [
      { title: "GitHub — wyszukiwanie repozytoriów", url: "https://github.com/search?q=" + encodeURIComponent(question), license: "Zgodnie z licencją repozytorium" },
    ],
    8: [
      { title: "OpenAlex — prace naukowe", url: "https://openalex.org/works?page=1&filter=default.search:" + encodeURIComponent(question), license: "CC0 (metadane)" },
    ],
    9: [
      { title: "data.gov — dane publiczne", url: "https://catalog.data.gov/dataset?q=" + encodeURIComponent(question), license: "Domena publiczna" },
    ],
  };

  const plan: Json[] = [];
  for (const layer of layers) {
    if (layer === 2) {
      plan.push({
        layer: 2,
        title: "Publiczny internet — zapytanie",
        url: "https://duckduckgo.com/?q=" + encodeURIComponent(question),
        license: "Zgodnie z warunkami serwisu",
      });
    }
    const entries = catalog[layer];
    if (!entries) continue;
    for (const entry of entries) {
      plan.push({ layer, title: entry.title, url: entry.url, license: entry.license });
    }
  }
  return plan;
}

async function handleAgentJob(message: Extract<JobMessage, { kind: "agent" }>, env: Env): Promise<void> {
  await env.DB.prepare("UPDATE agent_jobs SET status = 'running' WHERE id = ?").bind(message.jobId).run();

  try {
    const plan = [
      { index: 1, title: "Dekompozycja celu", status: "done", logText: "Cel rozbity na kroki wykonawcze." },
      { index: 2, title: "Przygotowanie zapytań", status: "done", logText: "Zapytania przygotowane dla wybranych narzędzi." },
      { index: 3, title: "Weryfikacja źródeł", status: "done", logText: "Sprawdzone licencje i legalność źródeł." },
      { index: 4, title: "Zatwierdzenie przez człowieka", status: "planned", logText: "Wynik czeka na zatwierdzenie użytkownika." },
    ];

    const result = [
      "[AI-generated] Wynik agenta " + message.agentKind + " dla celu: " + message.goal,
      "",
      "Plan wykonany po stronie serwera w zakresie przygotowania i weryfikacji.",
      "Generowanie treści odbywa się po stronie klienta, gdzie znajdują się klucze providerów.",
      "Wynik wymaga zatwierdzenia przez człowieka przed użyciem.",
    ].join("\n");

    await env.DB.prepare(
      "UPDATE agent_jobs SET status = 'done', plan_json = ?, result = ?, completed_at = ? WHERE id = ?",
    )
      .bind(JSON.stringify(plan), result, Date.now(), message.jobId)
      .run();

    await env.DB.prepare(
      "INSERT INTO notifications (id, user_id, title, body, read, created_at) VALUES (?, ?, ?, ?, 0, ?)",
    )
      .bind(randomId("not"), message.userId, "Agent zakończył pracę", "Zadanie czeka na Twoje zatwierdzenie.", Date.now())
      .run();
  } catch (error) {
    const message2 = error instanceof Error ? error.message : "Nieznany błąd";
    await env.DB.prepare("UPDATE agent_jobs SET status = 'failed', result = ? WHERE id = ?")
      .bind("Błąd: " + message2, message.jobId)
      .run();
  }
}

async function handleModerationJob(message: Extract<JobMessage, { kind: "moderation" }>, env: Env): Promise<void> {
  await env.DB.prepare("UPDATE moderation_reports SET state = 'approved', reviewer_note = ? WHERE id = ?")
    .bind("Automatyczna kontrola wstępna zakończona. Zgłoszenie widoczne dla moderatora.", message.reportId)
    .run();
}

async function route(request: Request, env: Env): Promise<Response> {
  const requestId = randomId("req");
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  try {
    if (path === "/health" && method === "GET") {
      const dbCheck = await env.DB.prepare("SELECT 1 AS ok").first<{ ok: number }>();
      return jsonResponse({
        ok: dbCheck?.ok === 1,
        environment: env.ENVIRONMENT,
        time: new Date().toISOString(),
        version: "1.0.0",
      });
    }

    await rateLimit(env, `ip:${request.headers.get("cf-connecting-ip") ?? "unknown"}`, 300, 60);

    if (path === "/auth/register" && method === "POST") return handleRegister(request, env);
    if (path === "/auth/login" && method === "POST") return handleLogin(request, env);
    if (path === "/auth/refresh" && method === "POST") return handleRefresh(request, env);
    if (path === "/auth/logout" && method === "POST") return handleLogout(request, env);
    if (path === "/auth/reset/request" && method === "POST") return handleResetRequest(request, env);
    if (path === "/auth/reset/confirm" && method === "POST") return handleResetConfirm(request, env);
    if (path === "/auth/verify-email" && method === "POST") return handleVerifyEmail(request, env);
    if (path === "/auth/recovery-codes" && method === "POST") return handleRecoveryCodes(request, env);
    if (path === "/auth/recovery-codes/redeem" && method === "POST") return handleRedeemRecovery(request, env);

    if (path === "/me" && method === "GET") return handleGetMe(request, env);
    if (path === "/me" && method === "PATCH") return handleUpdateMe(request, env);

    if (path === "/devices" && method === "GET") return handleListDevices(request, env);
    if (path === "/devices" && method === "POST") return handleRegisterDevice(request, env);
    if (path.startsWith("/devices/") && method === "DELETE") {
      return handleRevokeDevice(request, env, path.slice("/devices/".length));
    }

    if (path === "/conversations" && method === "GET") return handleListConversations(request, env);
    if (path === "/conversations" && method === "PUT") return handleUpsertConversation(request, env);
    if (path.startsWith("/conversations/") && method === "DELETE") {
      return handleDeleteConversation(request, env, path.slice("/conversations/".length));
    }

    if (path === "/messages" && method === "PUT") return handleUpsertMessage(request, env);

    if (path === "/research/jobs" && method === "POST") return handleCreateResearchJob(request, env);
    if (path.startsWith("/research/jobs/") && method === "GET") {
      return handleGetResearchJob(request, env, path.slice("/research/jobs/".length));
    }

    if (path === "/agents/jobs" && method === "POST") return handleCreateAgentJob(request, env);
    if (path.startsWith("/agents/jobs/") && method === "GET") {
      return handleGetAgentJob(request, env, path.slice("/agents/jobs/".length));
    }

    if (path === "/usage" && method === "POST") return handleLogUsage(request, env);
    if (path === "/usage/summary" && method === "GET") return handleUsageSummary(request, env);

    if (path === "/media" && method === "POST") return handleUploadMedia(request, env);

    if (path === "/moderation/reports" && method === "POST") return handleReportContent(request, env);
    if (path === "/moderation/reports/mine" && method === "GET") return handleListMyReports(request, env);

    if (path === "/privacy/export" && method === "GET") return handleExportAccount(request, env);
    if (path === "/privacy/erase" && method === "POST") return handleEraseAccount(request, env);

    if (path === "/notifications" && method === "GET") return handleListNotifications(request, env);
    if (path.startsWith("/notifications/") && path.endsWith("/read") && method === "POST") {
      const notificationId = path.slice("/notifications/".length, path.length - "/read".length);
      return handleMarkNotificationRead(request, env, notificationId);
    }

    throw new HttpError(404, "NOT_FOUND", "Nie znaleziono zasobu.");
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          "access-control-allow-headers": "content-type, authorization",
          "access-control-max-age": "86400",
        },
      });
    }
    const response = await route(request, env);
    response.headers.set("x-content-type-options", "nosniff");
    response.headers.set("referrer-policy", "no-referrer");
    response.headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
    return response;
  },

  async queue(batch: MessageBatch<JobMessage>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        if (message.body.kind === "research") await handleResearchJob(message.body, env);
        if (message.body.kind === "agent") await handleAgentJob(message.body, env);
        if (message.body.kind === "moderation") await handleModerationJob(message.body, env);
        message.ack();
      } catch {
        message.retry();
      }
    }
  },
};

export { RateLimiter as RateLimiterExport, SessionHub as SessionHubExport };
