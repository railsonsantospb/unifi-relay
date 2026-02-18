import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";

const PORT = Number(process.env.PORT || "5000");
const SHARED_SECRET = (process.env.RELAY_SHARED_SECRET || "").trim();

const TELEGRAM_BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || "").trim();
const TELEGRAM_CHAT_ID = (process.env.TELEGRAM_CHAT_ID || "").trim();

const DATA_DIR = (process.env.DATA_DIR || "/data").trim();
const STATE_FILE = path.join(DATA_DIR, "state.json");

type Device = { name: string; online: boolean };

type Payload = {
    type: "unifi.devices.v1";
    ts: string;
    site: string;
    mode: string;
    hash: string;
    devices: Device[];
};

function requireEnv() {
    const missing: string[] = [];
    if (!SHARED_SECRET) missing.push("RELAY_SHARED_SECRET");
    if (!TELEGRAM_BOT_TOKEN) missing.push("TELEGRAM_BOT_TOKEN");
    if (!TELEGRAM_CHAT_ID) missing.push("TELEGRAM_CHAT_ID");
    if (missing.length) throw new Error(`Faltam variáveis de ambiente: ${missing.join(", ")}`);
}

function readState(): Record<string, any> {
    try {
        return JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
    } catch {
        return {};
    }
}

function writeState(state: Record<string, any>) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf-8");
}

function timingSafeEqualHex(a: string, b: string) {
    const ab = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}

function verifySignature(rawBody: Buffer, headerSig: string | undefined) {
    if (!headerSig) return false;
    const mac = crypto.createHmac("sha256", SHARED_SECRET).update(rawBody).digest("hex");
    return timingSafeEqualHex(mac, headerSig);
}

async function tgSendMessage(text: string) {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ chat_id: TELEGRAM_CHAT_ID, text }),
    });
    if (!resp.ok) {
        const body = await resp.text().catch(() => "");
        throw new Error(`Telegram sendMessage falhou: ${resp.status} ${body}`);
    }
}

function formatReport(p: Payload): string {
    const online = p.devices.filter(d => d.online).length;
    const total = p.devices.length;

    const lines = p.devices.map(d => `- ${d.name}: ${d.online ? "🟢 ONLINE" : "🔴 OFFLINE"}`);
    return [
        `📶 UniFi Devices (${p.site})`,
        `🔧 Modo API: ${p.mode}`,
        `📊 Online: ${online}/${total}`,
        ``,
        ...lines,
    ].join("\n");
}

const app = express();

// Precisamos do RAW BODY para validar HMAC
app.use(express.raw({ type: "application/json", limit: "256kb" }));

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.post("/ingest/unifi", async (req, res) => {
    try {
        const sig = req.header("X-Signature") || undefined;
        const rawBody = req.body as Buffer;

        if (!verifySignature(rawBody, sig)) {
            return res.status(401).json({ ok: false, error: "invalid_signature" });
        }

        const payload = JSON.parse(rawBody.toString("utf-8")) as Payload;

        if (payload?.type !== "unifi.devices.v1") {
            return res.status(400).json({ ok: false, error: "invalid_payload_type" });
        }

        // chave por site (se você tiver múltiplos)
        const key = `unifi:${payload.site}`;
        const state = readState();
        const lastHash = state[key]?.hash as string | undefined;

        if (lastHash === payload.hash) {
            return res.json({ ok: true, changed: false });
        }

        // Atualiza estado e notifica Telegram
        state[key] = { hash: payload.hash, ts: payload.ts };
        writeState(state);

        const msg = formatReport(payload);
        await tgSendMessage(msg);

        return res.json({ ok: true, changed: true });
    } catch (e: any) {
        return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
});

requireEnv();
app.listen(PORT, () => console.log(`[relay] listening on :${PORT}`));
