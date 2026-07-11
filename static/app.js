/* ══════════════════════════════════════════
   Network Scanner — Dashboard JS
   Your devices guard
══════════════════════════════════════════ */

// ─── App State ───
let allDevices = [];
let allPending = [];
let renamingMac = null;
let activeSidePanel = "alerts"; // "alerts" | "settings"

// ─── Init ───────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    bootSequence();
});

async function bootSequence() {
    try {
        const wifi = await fetchJSON("/api/wifi/status");
        const status = await fetchJSON("/api/status");
        const root = status.root_user || {};

        if (wifi.connected) {
            // Already on a network — go to dashboard directly
            enterDashboard(wifi, status);
        } else {
            // Show WiFi setup wizard
            showSetupScreen();
        }

        // Load visible WiFi networks into dropdown
        loadNetworkList();

        // Pre-fill "already connected" section if applicable
        if (wifi.connected && wifi.ssid) {
            showElement("already-connected-area");
            setText("current-ssid-label", wifi.ssid);
        }

    } catch (e) {
        console.error("Boot error:", e);
        // On error (e.g. running on Render with no WiFi) go straight to dashboard
        enterDashboard(null, null);
    }
}

// ─── Screen Management ───────────────────
function showSetupScreen() {
    document.getElementById("screen-setup").classList.add("active");
    document.getElementById("screen-dashboard").classList.remove("active");
}

function enterDashboard(wifiStatus, sysStatus) {
    document.getElementById("screen-setup").classList.remove("active");
    document.getElementById("screen-dashboard").classList.add("active");

    if (wifiStatus) updateNetworkPill(wifiStatus);
    if (sysStatus) updateStats(sysStatus);

    // Start all polling
    refreshDashboard();
    setInterval(refreshDashboard, 5000);
}

function goToSetup() {
    showSetupScreen();
}

// ─── WiFi Setup Wizard ───────────────────
async function loadNetworkList() {
    const btn = document.getElementById("btn-refresh-networks");
    btn.querySelector("i").classList.add("fa-spin");
    try {
        const res = await fetchJSON("/api/wifi/networks");
        const networks = res.networks || [];
        const dropdown = document.getElementById("network-dropdown");

        if (networks.length === 0) {
            dropdown.classList.add("hidden");
            return;
        }

        dropdown.innerHTML = networks.map(ssid => `
            <div class="network-item" onclick="selectNetwork('${escHtml(ssid)}')">
                <i class="fa-solid fa-wifi"></i>
                <span>${escHtml(ssid)}</span>
            </div>
        `).join("");
        dropdown.classList.remove("hidden");
    } catch (e) {
        console.warn("Network scan failed:", e);
    } finally {
        btn.querySelector("i").classList.remove("fa-spin");
    }
}

function selectNetwork(ssid) {
    document.getElementById("inp-ssid").value = ssid;
    document.getElementById("network-dropdown").classList.add("hidden");
    document.getElementById("inp-password").focus();
}

function showNetworkForm() {
    hideElement("already-connected-area");
    showElement("network-form");
}

async function connectToWifi() {
    const ssid     = document.getElementById("inp-ssid").value.trim();
    const password = document.getElementById("inp-password").value;

    if (!ssid) { toast("Enter a WiFi network name (SSID)", "warning"); return; }

    // Show loading state
    setConnecting(true);

    try {
        const res = await postJSON("/api/wifi/connect", { ssid, password });

        if (res.success) {
            // Show success banner
            document.getElementById("connection-success-text").textContent = `✓ Connected to ${ssid}!`;
            document.getElementById("connection-success-banner").classList.remove("hidden");

            setTimeout(async () => {
                const wifi = await fetchJSON("/api/wifi/status");
                const status = await fetchJSON("/api/status");
                enterDashboard(wifi, status);
            }, 1800);

        } else {
            toast(res.message || "Connection failed. Check your password.", "error");
            setConnecting(false);
        }
    } catch (e) {
        toast("Connection error. Check server.", "error");
        setConnecting(false);
    }
}

function setConnecting(connecting) {
    const btn = document.getElementById("btn-connect");
    document.getElementById("btn-connect-text").classList.toggle("hidden", connecting);
    document.getElementById("btn-connect-loading").classList.toggle("hidden", !connecting);
    btn.disabled = connecting;
}

function togglePasswordVisibility() {
    const inp = document.getElementById("inp-password");
    const ico = document.getElementById("icon-eye");
    if (inp.type === "password") {
        inp.type = "text";
        ico.className = "fa-solid fa-eye-slash";
    } else {
        inp.type = "password";
        ico.className = "fa-solid fa-eye";
    }
}

// ─── Dashboard Refresh ───────────────────
async function refreshDashboard() {
    try {
        const [status, devices, alerts, pending] = await Promise.all([
            fetchJSON("/api/status"),
            fetchJSON("/api/devices"),
            fetchJSON("/api/alerts"),
            fetchJSON("/api/pending")
        ]);

        updateNetworkPill(status.network);
        updateStats(status);
        updateRootUserDisplay(status.root_user);

        allDevices = devices;
        allPending = pending;

        renderDevices();
        renderPendingSection(pending);

        if (activeSidePanel === "alerts") {
            renderAlerts(alerts);
        }

        // Alert dot on bell
        const dot = document.getElementById("alert-dot");
        if (status.counts.alerts_active > 0 || pending.length > 0) {
            dot.classList.remove("hidden");
        } else {
            dot.classList.add("hidden");
        }

        // Pre-fill webhook if set
        const whInput = document.getElementById("webhook-url-input");
        if (whInput && document.activeElement !== whInput && status.webhook_url) {
            whInput.value = status.webhook_url;
        }

        // Pre-fill agent config display
        refreshAgentConfigDisplay(status);

    } catch (e) {
        console.warn("Dashboard refresh error:", e);
    }
}

// ─── Network & Stats ─────────────────────
function updateNetworkPill(net) {
    if (!net) return;
    document.getElementById("topbar-ssid").textContent = net.ssid || "No WiFi";
    document.getElementById("topbar-gateway").textContent = net.gateway_ip || net.local_ip || "—";
}

function updateStats(status) {
    setText("stat-devices", status.counts?.devices ?? "—");
    setText("stat-alerts", status.counts?.alerts_active ?? "—");
    setText("stat-flows", status.counts?.traffic_logs ?? "—");
    setText("stat-mem", status.memory_usage_mb ?? "—");

    const elevEl   = document.getElementById("stat-elevation-text");
    const elevated = status.elevated;
    if (elevated !== undefined) {
        elevEl.textContent = elevated ? "Live Scan (Admin)" : "Observer Mode";
        elevEl.style.color = elevated ? "var(--green)" : "var(--orange)";
    }

    // Pending count badge
    const pendCount = status.counts?.pending_approval ?? 0;
    const badge = document.getElementById("pending-count-badge");
    if (badge) {
        badge.textContent = pendCount;
        badge.style.display = pendCount > 0 ? "inline-flex" : "none";
    }
}

function updateRootUserDisplay(rootUser) {
    if (!rootUser) return;
    const nameEl = document.getElementById("root-user-name-display");
    if (nameEl) {
        nameEl.textContent = rootUser.name || "Set up Admin";
    }
}

function refreshAgentConfigDisplay(status) {
    const agentBadge = document.getElementById("agent-status-badge");
    if (agentBadge) {
        if (status.agent_configured) {
            agentBadge.textContent = "WhatsApp Active";
            agentBadge.className = "badge badge-green";
        } else {
            agentBadge.textContent = "Not Configured";
            agentBadge.className = "badge badge-orange";
        }
    }
    const tgBadge = document.getElementById("telegram-status-badge");
    if (tgBadge) {
        if (status.telegram_configured) {
            tgBadge.textContent = "Telegram Active";
            tgBadge.className = "badge badge-green";
        } else {
            tgBadge.textContent = "Not Configured";
            tgBadge.className = "badge badge-orange";
        }
    }
}

// ─── Device Grid ─────────────────────────
function renderDevices() {
    const grid   = document.getElementById("devices-grid");
    const filter = (document.getElementById("device-filter")?.value || "").toLowerCase();

    const filtered = allDevices.filter(d => {
        const name = (d.custom_name || d.hostname || "").toLowerCase();
        const ip   = (d.last_known_ip || "").toLowerCase();
        const mac  = (d.mac_address || "").toLowerCase();
        return name.includes(filter) || ip.includes(filter) || mac.includes(filter);
    });

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div style="grid-column:1/-1; padding:3rem; text-align:center; color:var(--text-3);">
                <i class="fa-solid fa-magnifying-glass" style="font-size:2rem;display:block;margin-bottom:0.75rem;"></i>
                No devices found. Run a scan to discover devices on your network.
            </div>`;
        return;
    }

    grid.innerHTML = filtered.map(d => buildDeviceCard(d)).join("");
}

function buildDeviceCard(d) {
    const name     = d.custom_name || d.hostname || `Device-${(d.mac_address || "").slice(-5).replace(":", "")}`;
    const hostname = d.hostname && d.hostname !== name ? d.hostname : "";
    const blocked  = d.is_blocked;
    const approved = d.is_approved === 1;
    const pending  = d.is_approved === 0;

    let statusBadge = "";
    if (blocked) {
        statusBadge = `<span class="badge badge-red"><i class="fa-solid fa-ban"></i> Blocked</span>`;
    } else if (approved) {
        statusBadge = `<span class="badge badge-green"><i class="fa-solid fa-check"></i> Approved</span>`;
    } else {
        statusBadge = `<span class="badge badge-orange"><i class="fa-solid fa-clock"></i> Pending</span>`;
    }

    const icon = guessDeviceIcon(d);
    const mac  = encodeURIComponent(d.mac_address);

    return `
    <div class="device-card ${blocked ? "device-card-blocked" : ""}">
        <div class="device-card-top">
            <div class="device-icon-wrap">${icon}</div>
            <div class="device-online-dot ${blocked ? "dot-blocked" : ""}"></div>
        </div>
        <div>
            <div class="device-name">${escHtml(name)}</div>
            ${hostname ? `<div class="device-hostname">${escHtml(hostname)}</div>` : ""}
        </div>
        <div class="device-details">
            <div class="detail-row">
                <span class="label">IP</span>
                <span class="value">${escHtml(d.last_known_ip || "—")}</span>
            </div>
            <div class="detail-row">
                <span class="label">MAC</span>
                <span class="value">${escHtml(d.mac_address || "—")}</span>
            </div>
            <div class="detail-row">
                <span class="label">Last seen</span>
                <span class="value">${timeAgo(d.last_seen)}</span>
            </div>
        </div>
        <div style="margin-top:0.25rem;">${statusBadge}</div>
        <div class="device-card-footer">
            <button class="btn btn-ghost btn-sm" onclick="openRenameModal('${mac}', '${escHtml(d.mac_address)}', '${escHtml(name)}')" title="Rename">
                <i class="fa-solid fa-pencil"></i>
            </button>
            ${!blocked
                ? `<button class="btn btn-danger btn-sm" onclick="blockDevice('${mac}', '${escHtml(name)}')" title="Block device">
                       <i class="fa-solid fa-ban"></i> Block
                   </button>`
                : `<button class="btn btn-ghost btn-sm" onclick="unblockDevice('${mac}', '${escHtml(name)}')" title="Unblock">
                       <i class="fa-solid fa-lock-open"></i> Unblock
                   </button>`
            }
            ${pending && !blocked
                ? `<button class="btn btn-primary btn-sm" onclick="allowDevice('${mac}')" title="Approve">
                       <i class="fa-solid fa-check"></i>
                   </button>`
                : ""
            }
        </div>
    </div>`;
}

function guessDeviceIcon(d) {
    const name = (d.custom_name || d.hostname || "").toLowerCase();
    if (name.includes("iphone") || name.includes("android") || name.includes("phone") || name.includes("mobile"))
        return '<i class="fa-solid fa-mobile-screen"></i>';
    if (name.includes("ipad") || name.includes("tablet"))
        return '<i class="fa-solid fa-tablet"></i>';
    if (name.includes("tv") || name.includes("television") || name.includes("roku") || name.includes("firetv"))
        return '<i class="fa-solid fa-tv"></i>';
    if (name.includes("printer") || name.includes("print"))
        return '<i class="fa-solid fa-print"></i>';
    if (name.includes("router") || name.includes("gateway") || name.includes("ap-"))
        return '<i class="fa-solid fa-wifi"></i>';
    if (name.includes("camera") || name.includes("cam"))
        return '<i class="fa-solid fa-camera"></i>';
    if (name.includes("mac") || name.includes("macbook") || name.includes("imac"))
        return '<i class="fa-brands fa-apple"></i>';
    if (name.includes("windows") || name.includes("desktop") || name.includes("pc"))
        return '<i class="fa-brands fa-windows"></i>';
    if (name.includes("raspberry") || name.includes("pi"))
        return '<i class="fa-brands fa-raspberry-pi"></i>';
    return '<i class="fa-solid fa-laptop-code"></i>';
}

// ─── Pending Approvals Section ───────────
function renderPendingSection(pending) {
    const section = document.getElementById("pending-section");
    if (!section) return;

    if (pending.length === 0) {
        section.classList.add("hidden");
        return;
    }

    section.classList.remove("hidden");
    const list = document.getElementById("pending-list");
    list.innerHTML = pending.map(d => {
        const name = d.hostname || `Device-${(d.mac_address || "").slice(-5)}`;
        const mac  = encodeURIComponent(d.mac_address);
        return `
        <div class="pending-card">
            <div class="pending-info">
                <i class="fa-solid fa-circle-question"></i>
                <div>
                    <strong>${escHtml(name)}</strong>
                    <span class="pending-meta">${escHtml(d.last_known_ip)} · ${escHtml(d.mac_address)}</span>
                </div>
            </div>
            <div class="pending-actions">
                <button class="btn btn-primary btn-sm" onclick="allowDevice('${mac}')"><i class="fa-solid fa-check"></i> Allow</button>
                <button class="btn btn-danger btn-sm" onclick="blockDevice('${mac}', '${escHtml(name)}')"><i class="fa-solid fa-ban"></i> Block</button>
            </div>
        </div>`;
    }).join("");
}

// ─── Device Actions ──────────────────────
async function blockDevice(encodedMac, name) {
    if (!confirm(`Block "${name}" from your network? This will add an OS firewall rule.`)) return;
    const mac = decodeURIComponent(encodedMac);
    const res = await postJSON(`/api/devices/${encodeURIComponent(mac)}/block`);
    if (res.success) {
        toast(`${name} has been blocked.`, "success");
        refreshDashboard();
    } else {
        toast(res.message || "Block failed.", "error");
    }
}

async function allowDevice(encodedMac) {
    const mac = decodeURIComponent(encodedMac);
    const res = await postJSON(`/api/devices/${encodeURIComponent(mac)}/allow`);
    if (res.success) {
        toast("Device approved.", "success");
        refreshDashboard();
    } else {
        toast(res.message || "Failed to approve.", "error");
    }
}

async function unblockDevice(encodedMac, name) {
    const mac = decodeURIComponent(encodedMac);
    const res = await postJSON(`/api/devices/${encodeURIComponent(mac)}/unblock`);
    if (res.success) {
        toast(`${name} has been unblocked.`, "success");
        refreshDashboard();
    } else {
        toast(res.message || "Unblock failed. Requires admin privileges.", "error");
    }
}

// ─── Alerts Panel ────────────────────────
function showAlertsPanel() {
    activeSidePanel = "alerts";
    showElement("panel-alerts");
    hideElement("panel-settings");
    fetchJSON("/api/alerts").then(renderAlerts);
}

function showSettingsPanel() {
    activeSidePanel = "settings";
    showElement("panel-settings");
    hideElement("panel-alerts");
}

async function fetchAlerts() {
    const alerts = await fetchJSON("/api/alerts");
    renderAlerts(alerts);
}

function renderAlerts(alerts) {
    const list = document.getElementById("alerts-list");
    if (!alerts || alerts.length === 0) {
        list.innerHTML = `<div class="empty-msg"><i class="fa-solid fa-shield-check"></i> No active alerts</div>`;
        return;
    }

    list.innerHTML = alerts.map(a => {
        const icon = a.severity === "HIGH" ? "fa-triangle-exclamation" :
                     a.severity === "MEDIUM" ? "fa-shield-halved" : "fa-circle-info";
        return `
        <div class="alert-card ${a.severity} ${a.is_resolved ? "resolved" : ""}">
            <div class="alert-card-top">
                <i class="fa-solid ${icon}"></i>
                <span class="alert-type-label">${a.alert_type}</span>
                ${!a.is_resolved ? `<button class="alert-resolve-btn" onclick="resolveAlert(${a.id})" title="Mark resolved">
                    <i class="fa-solid fa-check"></i>
                </button>` : ""}
            </div>
            <div class="alert-description">${escHtml(a.description)}</div>
            <div class="alert-time">${formatDate(a.timestamp)}</div>
        </div>`;
    }).join("");
}

async function resolveAlert(id) {
    await postJSON(`/api/alerts/resolve/${id}`);
    fetchAlerts();
    refreshDashboard();
}

async function resolveAllAlerts() {
    await postJSON("/api/alerts/resolve-all");
    fetchAlerts();
    refreshDashboard();
    toast("All alerts cleared.", "success");
}

// ─── Scan Trigger ────────────────────────
async function triggerScan() {
    const btn = document.getElementById("btn-scan-now");
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
    btn.disabled = true;
    try {
        const res = await postJSON("/api/scan/trigger");
        toast(res.message || "Scan triggered.", "success");
        setTimeout(refreshDashboard, 3000);
    } catch (e) {
        toast("Scan failed.", "error");
    } finally {
        setTimeout(() => {
            btn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i>';
            btn.disabled = false;
        }, 2000);
    }
}

// ─── Root User Setup ─────────────────────
function showRootUserSetup() {
    document.getElementById("root-user-modal").classList.remove("hidden");
    // Pre-fill if data exists
    fetchJSON("/api/root-user").then(u => {
        if (u.name) document.getElementById("inp-root-name").value = u.name;
        if (u.phone) document.getElementById("inp-root-phone").value = u.phone;
    });
}

function closeRootUserModal() {
    document.getElementById("root-user-modal").classList.add("hidden");
}

async function saveRootUser() {
    const name  = document.getElementById("inp-root-name").value.trim();
    const phone = document.getElementById("inp-root-phone").value.trim();
    if (!name || !phone) { toast("Both name and phone number are required.", "warning"); return; }

    const res = await postJSON("/api/root-user/setup", { name, phone });
    if (res.success) {
        toast(`Admin '${name}' saved. WhatsApp alerts will be sent to ${phone}.`, "success");
        closeRootUserModal();
        refreshDashboard();
    } else {
        toast(res.message || "Failed to save admin.", "error");
    }
}

// ─── Agent (Twilio WhatsApp) Config ──────
function showAgentSettings() {
    // Load current config
    fetchJSON("/api/agent/config").then(cfg => {
        const sidEl = document.getElementById("inp-twilio-sid");
        const numEl = document.getElementById("inp-twilio-from");
        if (sidEl) sidEl.value = cfg.account_sid || "";
        if (numEl) numEl.value = cfg.from_number || "";
    });
    document.getElementById("agent-config-modal").classList.remove("hidden");
}

function closeAgentModal() {
    document.getElementById("agent-config-modal").classList.add("hidden");
}

async function saveAgentConfig() {
    const account_sid  = document.getElementById("inp-twilio-sid").value.trim();
    const auth_token   = document.getElementById("inp-twilio-token").value.trim();
    const from_number  = document.getElementById("inp-twilio-from").value.trim();
    const use_whatsapp = true; // Always WhatsApp

    const payload = { account_sid, from_number, use_whatsapp };
    if (auth_token) payload.auth_token = auth_token;

    const res = await postJSON("/api/agent/config", payload);
    if (res.success) {
        toast(res.configured ? "Agent configured. WhatsApp alerts active!" : "Saved. Fill all fields to activate alerts.", "success");
        closeAgentModal();
        refreshDashboard();
    } else {
        toast("Failed to save agent config.", "error");
    }
}

async function testAgentAlert() {
    const res = await postJSON("/api/agent/test");
    if (res.success) {
        toast("Test WhatsApp message sent!", "success");
    } else {
        toast(res.message || "Agent not configured yet.", "warning");
    }
}

// ─── Agent (Telegram Bot) Config ─────────
function showTelegramSettings() {
    fetchJSON("/api/telegram/config").then(cfg => {
        const chatEl = document.getElementById("inp-telegram-chat");
        if (chatEl) chatEl.value = cfg.chat_id || "";
    });
    document.getElementById("telegram-config-modal").classList.remove("hidden");
}

function closeTelegramModal() {
    document.getElementById("telegram-config-modal").classList.add("hidden");
}

async function saveTelegramConfig() {
    const bot_token = document.getElementById("inp-telegram-token").value.trim();
    const chat_id   = document.getElementById("inp-telegram-chat").value.trim();

    const payload = { chat_id };
    if (bot_token) payload.bot_token = bot_token;

    const res = await postJSON("/api/telegram/config", payload);
    if (res.success) {
        toast(res.configured ? "Telegram Bot configured successfully!" : "Saved. Fill both fields to activate bot.", "success");
        closeTelegramModal();
        refreshDashboard();
    } else {
        toast("Failed to save Telegram configuration.", "error");
    }
}

async function testTelegramAlert() {
    const res = await postJSON("/api/telegram/test");
    if (res.success) {
        toast("Test Telegram alert sent!", "success");
    } else {
        toast(res.message || "Telegram Bot not configured yet.", "warning");
    }
}

// ─── Settings Panel Actions ──────────────
async function saveWebhook() {
    const url = document.getElementById("webhook-url-input").value.trim();
    const res = await postJSON("/api/config/update", { webhook_url: url });
    if (res.success) toast("Webhook saved.", "success");
}

async function testWebhook() {
    const res = await postJSON("/api/webhook/test");
    toast(res.success ? "Test alert dispatched." : res.message, res.success ? "success" : "warning");
}

async function purgeOldLogs() {
    if (!confirm("Purge all traffic logs older than 7 days?")) return;
    const res = await postJSON("/api/purge");
    toast(res.message || "Done.", "success");
}

// ─── Rename Modal ────────────────────────
function openRenameModal(encodedMac, macDisplay, currentName) {
    renamingMac = decodeURIComponent(encodedMac);
    document.getElementById("rename-device-info").textContent = `MAC: ${macDisplay}`;
    document.getElementById("rename-input").value = currentName;
    document.getElementById("rename-modal").classList.remove("hidden");
    setTimeout(() => document.getElementById("rename-input").select(), 50);
}

function closeRenameModal(event) {
    if (event.target === document.getElementById("rename-modal")) {
        closeRenameModalBtn();
    }
}

function closeRenameModalBtn() {
    document.getElementById("rename-modal").classList.add("hidden");
    renamingMac = null;
}

async function submitRename() {
    if (!renamingMac) return;
    const name = document.getElementById("rename-input").value.trim();
    if (!name) { toast("Name cannot be empty.", "warning"); return; }

    const res = await postJSON(`/api/devices/${encodeURIComponent(renamingMac)}/rename`, { name });
    if (res.success) {
        toast(`Device renamed to "${name}".`, "success");
        closeRenameModalBtn();
        refreshDashboard();
    } else {
        toast(res.message || "Rename failed.", "error");
    }
}

// ─── Toast Notifications ─────────────────
function toast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    const icons = { success: "fa-circle-check", error: "fa-circle-exclamation", warning: "fa-triangle-exclamation", info: "fa-circle-info" };
    el.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${escHtml(message)}</span>`;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4500);
}

// ─── Helpers ─────────────────────────────
async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

async function postJSON(url, body = {}) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
    return res.json();
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function showElement(id) {
    document.getElementById(id)?.classList.remove("hidden");
}

function hideElement(id) {
    document.getElementById(id)?.classList.add("hidden");
}

function escHtml(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function timeAgo(isoStr) {
    if (!isoStr) return "—";
    try {
        const date = new Date(isoStr.replace(" ", "T"));
        const diff = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diff < 60) return "just now";
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch { return isoStr; }
}

function formatDate(isoStr) {
    if (!isoStr) return "";
    try {
        const d = new Date(isoStr.replace(" ", "T"));
        return d.toLocaleString();
    } catch { return isoStr; }
}
