/**
 * hmh-AIOS-dang-video-tiktok — thư viện dùng chung
 * Config loader + TikTok OAuth (PKCE) + TikTok Content Posting API (Upload to Inbox) + Lark Base helpers.
 * Node >= 18, zero-dependency.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CONFIG = path.join(__dirname, "config.local.json");
export const TT_OPEN = "https://open.tiktokapis.com";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Content Posting API: chunk 5MB–64MB khi chia nhiều mảnh; video < 4GB.
export const MAX_CHUNK = 64 * 1024 * 1024;

export function loadConfig(configPath = DEFAULT_CONFIG) {
  let CFG = {};
  try { CFG = JSON.parse(fs.readFileSync(configPath, "utf8")); } catch { /* dùng ENV (CI) */ }
  const E = process.env;
  CFG.__path        = configPath;
  CFG.larkDomain    = E.LARK_DOMAIN          || CFG.larkDomain || "https://open.larksuite.com";
  CFG.larkAppId     = E.LARK_APP_ID          || CFG.larkAppId;
  CFG.larkAppSecret = E.LARK_APP_SECRET      || CFG.larkAppSecret;
  CFG.appToken      = E.LARK_BASE_ID         || CFG.appToken;
  CFG.tablePost     = E.TABLE_POST           || CFG.tablePost;
  CFG.clientKey     = E.TIKTOK_CLIENT_KEY    || CFG.clientKey;
  CFG.clientSecret  = E.TIKTOK_CLIENT_SECRET || CFG.clientSecret;
  CFG.redirectUri   = E.TIKTOK_REDIRECT_URI  || CFG.redirectUri;
  CFG.refreshToken  = E.TIKTOK_REFRESH_TOKEN || CFG.refreshToken;
  CFG.accessToken   = E.TIKTOK_ACCESS_TOKEN  || CFG.accessToken;

  // TikTok xoay refresh_token mỗi lần refresh (bản cũ chết ngay). Nếu nhiều skill cùng dùng 1 app,
  // mỗi skill giữ 1 bản token riêng sẽ hỏng. "tokenFile" trỏ tất cả về CHUNG một kho token.
  CFG.__tokenPath = configPath;
  if (CFG.tokenFile) {
    const tp = path.resolve(path.dirname(configPath), CFG.tokenFile);
    try {
      const store = JSON.parse(fs.readFileSync(tp, "utf8"));
      if (store.refreshToken) CFG.refreshToken = E.TIKTOK_REFRESH_TOKEN || store.refreshToken;
      CFG.__tokenPath = tp;
    } catch { console.error(`Cảnh báo: không đọc được tokenFile ${tp} — dùng token trong config.local.json.`); }
  }
  return CFG;
}

export function requireKeys(CFG, keys) {
  for (const k of keys) {
    if (!CFG[k]) { console.error(`Thiếu cấu hình "${k}" (điền config.local.json hoặc set biến môi trường).`); process.exit(1); }
  }
}

/** Ghi vài khoá vào config.local.json (giữ nguyên phần còn lại). */
export function patchConfig(patch, configPath = DEFAULT_CONFIG) {
  let obj = {};
  try { obj = JSON.parse(fs.readFileSync(configPath, "utf8")); } catch {}
  Object.assign(obj, patch);
  fs.writeFileSync(configPath, JSON.stringify(obj, null, 2) + "\n");
}

// ---------- PKCE (Login Kit Desktop bắt buộc) ----------
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export function makePkce() {
  const verifier = b64url(crypto.randomBytes(48));
  // TikTok lệch chuẩn RFC 7636: code_challenge là SHA-256 dạng HEX, không phải base64url.
  const challenge = crypto.createHash("sha256").update(verifier).digest("hex");
  return { verifier, challenge };
}

// ---------- TikTok OAuth ----------
// Đăng vào Hộp thư/nháp cần scope video.upload (KHÔNG cần app audit).
// Xin TRỌN scope cho cả 2 chiều trong 1 lần ủy quyền — dùng chung 1 refresh token cho mọi script.
export const FULL_SCOPE = "user.info.basic,user.info.profile,user.info.stats,video.list,video.upload";

export function authorizeUrl(CFG, { codeChallenge, scope = FULL_SCOPE, state = "hmh" } = {}) {
  const u = new URL("https://www.tiktok.com/v2/auth/authorize/");
  u.searchParams.set("client_key", CFG.clientKey);
  u.searchParams.set("scope", scope);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("redirect_uri", CFG.redirectUri);
  u.searchParams.set("state", state);
  if (codeChallenge) {
    u.searchParams.set("code_challenge", codeChallenge);
    u.searchParams.set("code_challenge_method", "S256");
  }
  return u.toString();
}

async function ttTokenRequest(form) {
  const r = await fetch(`${TT_OPEN}/v2/oauth/token/`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache" },
    body: new URLSearchParams(form),
  });
  const j = await r.json();
  if (j.error && j.error !== "" && j.access_token == null) {
    throw new Error(`TikTok OAuth lỗi: ${j.error} — ${j.error_description || ""}`);
  }
  return j;
}

export function exchangeCode(CFG, code, codeVerifier) {
  const form = {
    client_key: CFG.clientKey, client_secret: CFG.clientSecret,
    code, grant_type: "authorization_code", redirect_uri: CFG.redirectUri,
  };
  if (codeVerifier) form.code_verifier = codeVerifier;
  return ttTokenRequest(form);
}

export function refreshAccessToken(CFG) {
  return ttTokenRequest({
    client_key: CFG.clientKey, client_secret: CFG.clientSecret,
    grant_type: "refresh_token", refresh_token: CFG.refreshToken,
  });
}

let _at = null, _atExp = 0;
export async function getAccessToken(CFG) {
  if (_at && Date.now() < _atExp) return _at;
  if (CFG.refreshToken) {
    requireKeys(CFG, ["clientKey", "clientSecret", "refreshToken"]);
    const j = await refreshAccessToken(CFG);
    _at = j.access_token;
    _atExp = Date.now() + ((j.expires_in || 86400) - 120) * 1000;
    if (j.refresh_token && j.refresh_token !== CFG.refreshToken) {
      CFG.refreshToken = j.refresh_token;
      try { patchConfig({ refreshToken: j.refresh_token }, CFG.__tokenPath || CFG.__path); } catch {}
    }
    return _at;
  }
  if (CFG.accessToken) { _at = CFG.accessToken; _atExp = Date.now() + 3600 * 1000; return _at; }
  console.error('Thiếu "refreshToken" (khuyên dùng) hoặc "accessToken". Chạy get-tiktok-token.mjs để lấy.');
  process.exit(1);
}

// ---------- TikTok Content Posting API — Upload to Inbox ----------
// Luồng: init (lấy publish_id + upload_url) -> PUT các mảnh bytes -> poll status.
// Video vào MỤC HỘP THƯ/NHÁP của người dùng; họ mở app TikTok để hoàn tất caption & đăng.
export async function inboxInit(CFG, { videoSize, chunkSize, totalChunkCount }) {
  const at = await getAccessToken(CFG);
  const r = await fetch(`${TT_OPEN}/v2/post/publish/inbox/video/init/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${at}`, "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify({
      source_info: { source: "FILE_UPLOAD", video_size: videoSize, chunk_size: chunkSize, total_chunk_count: totalChunkCount },
    }),
  });
  const j = await r.json();
  const err = j.error || {};
  if (err.code && err.code !== "ok") {
    throw new Error(`TikTok inbox init lỗi: ${err.code} — ${err.message || ""} (log_id ${err.log_id || "?"})`);
  }
  if (!j.data || !j.data.upload_url) throw new Error(`TikTok inbox init: thiếu upload_url — ${JSON.stringify(j)}`);
  return j.data; // { publish_id, upload_url }
}

/** PUT 1 mảnh bytes lên upload_url. TikTok trả 206 (mảnh) / 201 (hoàn tất). */
export async function uploadChunk(uploadUrl, buf, start, end, total, mime = "video/mp4") {
  const r = await fetch(uploadUrl, {
    method: "PUT",
    headers: {
      "Content-Type": mime,
      "Content-Length": String(buf.length),
      "Content-Range": `bytes ${start}-${end}/${total}`,
    },
    body: buf,
  });
  if (![200, 201, 206].includes(r.status)) {
    throw new Error(`Upload mảnh (bytes ${start}-${end}) lỗi ${r.status}: ${(await r.text()).slice(0, 300)}`);
  }
}

/** Đọc file rồi đẩy toàn bộ theo mảnh 5–64MB (TikTok gộp phần dư vào mảnh cuối). */
export async function uploadFileToInbox(CFG, filePath, mime = "video/mp4") {
  const size = fs.statSync(filePath).size;
  let chunkSize, totalChunkCount;
  if (size <= MAX_CHUNK) { chunkSize = size; totalChunkCount = 1; }
  else { chunkSize = MAX_CHUNK; totalChunkCount = Math.floor(size / chunkSize); }

  const { publish_id, upload_url } = await inboxInit(CFG, { videoSize: size, chunkSize, totalChunkCount });
  const fd = fs.openSync(filePath, "r");
  try {
    for (let i = 0; i < totalChunkCount; i++) {
      const start = i * chunkSize;
      const end = i === totalChunkCount - 1 ? size : start + chunkSize; // mảnh cuối lấy hết phần còn lại
      const len = end - start;
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, start);
      await uploadChunk(upload_url, buf, start, end - 1, size, mime);
    }
  } finally { fs.closeSync(fd); }
  return publish_id;
}

export async function fetchStatus(CFG, publishId) {
  const at = await getAccessToken(CFG);
  const r = await fetch(`${TT_OPEN}/v2/post/publish/status/fetch/`, {
    method: "POST",
    headers: { Authorization: `Bearer ${at}`, "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify({ publish_id: publishId }),
  });
  const j = await r.json();
  return j.data || {}; // { status: PROCESSING_UPLOAD | SEND_TO_USER_INBOX | FAILED ..., fail_reason }
}

// ---------- Lark Base ----------
let TOKEN = null, TOKEN_EXP = 0;
export async function larkToken(CFG) {
  if (TOKEN && Date.now() < TOKEN_EXP) return TOKEN;
  const r = await fetch(`${CFG.larkDomain}/open-apis/auth/v3/tenant_access_token/internal`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ app_id: CFG.larkAppId, app_secret: CFG.larkAppSecret }),
  });
  const j = await r.json();
  if (j.code !== 0) throw new Error(`Lark token lỗi: ${j.code} ${j.msg}`);
  TOKEN = j.tenant_access_token; TOKEN_EXP = Date.now() + (j.expire - 120) * 1000;
  return TOKEN;
}

export async function larkApi(CFG, method, apiPath, body) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const token = await larkToken(CFG);
    const r = await fetch(`${CFG.larkDomain}${apiPath}`, {
      method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const j = await r.json();
    if (j.code === 0) return j.data;
    if (j.code === 99991663 || j.code === 99991661) { TOKEN = null; continue; }
    if (r.status === 429 || j.code === 1254607 || j.code === 1254045) { await sleep(1200 * (attempt + 1)); continue; }
    throw new Error(`Lark ${apiPath} lỗi: ${j.code} ${j.msg}`);
  }
  throw new Error(`Lark ${apiPath}: hết lượt thử.`);
}

/** Tải attachment từ Lark về đĩa; trả về kích thước (bytes).
 * Attachment nằm TRONG Bitable đòi tham số ?extra={"bitablePerm":{"tableId":...}} —
 * thiếu nó Lark trả 400. Thử kèm extra trước (dùng tablePost), rớt về URL trần nếu vẫn cần. */
export async function downloadAttachment(CFG, fileToken, destPath) {
  const token = await larkToken(CFG);
  const base = `${CFG.larkDomain}/open-apis/drive/v1/medias/${fileToken}/download`;
  const urls = [];
  if (CFG.tablePost) {
    const extra = encodeURIComponent(JSON.stringify({ bitablePerm: { tableId: CFG.tablePost } }));
    urls.push(`${base}?extra=${extra}`);
  }
  urls.push(base);
  let lastStatus = 0;
  for (const url of urls) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok || (r.headers.get("content-type") || "").includes("application/json")) { lastStatus = r.status; continue; }
    await new Promise((res, rej) => {
      const ws = fs.createWriteStream(destPath);
      Readable.fromWeb(r.body).pipe(ws); ws.on("finish", res); ws.on("error", rej);
    });
    return fs.statSync(destPath).size;
  }
  throw new Error(`Tải video từ Lark lỗi ${lastStatus || "?"}`);
}

export async function listAllRecords(CFG, tableId) {
  const out = []; let pt = null;
  do {
    const qs = new URLSearchParams({ page_size: "200" });
    if (pt) qs.set("page_token", pt);
    const d = await larkApi(CFG, "GET", `/open-apis/bitable/v1/apps/${CFG.appToken}/tables/${tableId}/records?${qs}`);
    out.push(...(d.items || [])); pt = d.has_more ? d.page_token : null;
  } while (pt);
  return out;
}

export const updateRecord = (CFG, tableId, recordId, fields) =>
  larkApi(CFG, "PUT", `/open-apis/bitable/v1/apps/${CFG.appToken}/tables/${tableId}/records/${recordId}`, { fields });
