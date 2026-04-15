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

// Tempo máximo sem heartbeat antes de alertar (padrão: 3× o intervalo de 60s)
const HEARTBEAT_TIMEOUT_MS = Number(process.env.HEARTBEAT_TIMEOUT_SECONDS || "180") * 1000;

type Device = {
    name: string;
    online: boolean;
    tx_bytes?: number;   // UniFi: bytes enviados para clientes (download dos clientes)
    rx_bytes?: number;   // UniFi: bytes recebidos dos clientes (upload dos clientes)
    download?: number;   // Omada: bytes baixados pelos clientes
    upload?: number;     // Omada: bytes enviados pelos clientes
};

function fmtBytes(n: number): string {
    if (n >= 1_073_741_824) return `${(n / 1_073_741_824).toFixed(1)}GB`;
    if (n >= 1_048_576)     return `${(n / 1_048_576).toFixed(1)}MB`;
    if (n >= 1_024)         return `${(n / 1_024).toFixed(1)}KB`;
    return `${n}B`;
}

type Payload = {
    type: "unifi.devices.v1";
    ts: string;
    site: string;
    mode: string;
    hash: string;
    devices: Device[];
    omada_devices?: Device[];
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

    const unifiLines = p.devices.map(d => {
        const status = d.online ? "🟢" : "🔴";
        const dl = fmtBytes(d.tx_bytes ?? 0);
        const ul = fmtBytes(d.rx_bytes ?? 0);
        return `${status} ${d.name}  ↓${dl} ↑${ul}`;
    });

    const parts = [
        `📶 UniFi APs (${p.site})`,
        `🔧 Modo API: ${p.mode}`,
        `📊 Online: ${online}/${total}`,
        ``,
        ...unifiLines,
    ];

    if (p.omada_devices && p.omada_devices.length > 0) {
        const omadaOnline = p.omada_devices.filter(d => d.online).length;
        const omadaTotal = p.omada_devices.length;
        const omadaLines = p.omada_devices.map(d => {
            const status = d.online ? "🟢" : "🔴";
            const dl = fmtBytes(d.download ?? 0);
            const ul = fmtBytes(d.upload ?? 0);
            return `${status} ${d.name}  ↓${dl} ↑${ul}`;
        });

        parts.push(
            ``,
            `📡 Omada APs`,
            `📊 Online: ${omadaOnline}/${omadaTotal}`,
            ``,
            ...omadaLines,
        );
    }

    return parts.join("\n");
}

const app = express();

// Precisamos do RAW BODY para validar HMAC
app.use(express.raw({ type: "application/json", limit: "256kb" }));

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.post("/ingest/heartbeat", async (req, res) => {
    const sig = req.header("X-Signature") || undefined;
    if (!verifySignature(req.body as Buffer, sig)) {
        return res.status(401).json({ ok: false, error: "invalid_signature" });
    }

    try {
        const body = JSON.parse((req.body as Buffer).toString("utf-8"));
        const agentId: string = body.agent_id || "unknown";
        const agentName: string = body.agent_name || agentId;
        const key = `heartbeat:${agentId}`;

        const state = readState();
        const wasAlerted = state[key]?.alerted === true;

        state[key] = {
            agent_name: agentName,
            last_seen: new Date().toISOString(),
            alerted: false,
        };
        writeState(state);

        // Agente voltou depois de um alerta de queda
        if (wasAlerted) {
            const msg = `✅ Agente voltou\n🤖 ${agentName}\n🕐 ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`;
            await tgSendMessage(msg).catch(e => console.error("[relay] tg recovery erro:", e));
        }
    } catch (e) {
        console.error("[relay] heartbeat parse erro:", e);
    }

    return res.json({ ok: true });
});

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

function startHeartbeatWatchdog() {
    setInterval(async () => {
        const state = readState();
        const now = Date.now();

        for (const key of Object.keys(state)) {
            if (!key.startsWith("heartbeat:")) continue;

            const entry = state[key];
            const lastSeen = new Date(entry.last_seen).getTime();
            const elapsed = now - lastSeen;

            if (elapsed > HEARTBEAT_TIMEOUT_MS && !entry.alerted) {
                const agentName: string = entry.agent_name || key;
                const mins = Math.floor(elapsed / 60_000);
                const msg = `⚠️ Agente offline!\n🤖 ${agentName}\n⏱ Sem sinal há ${mins} min\n🕐 Último contato: ${new Date(entry.last_seen).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`;

                try {
                    await tgSendMessage(msg);
                    state[key].alerted = true;
                    writeState(state);
                    console.log(`[relay] alerta enviado: agente ${agentName} offline`);
                } catch (e) {
                    console.error("[relay] watchdog tg erro:", e);
                }
            }
        }
    }, 60_000); // verifica a cada 1 minuto
}

requireEnv();
app.listen(PORT, () => {
    console.log(`[relay] listening on :${PORT}`);
    console.log(`[relay] watchdog: alerta após ${HEARTBEAT_TIMEOUT_MS / 1000}s sem heartbeat`);
    startHeartbeatWatchdog();
});
