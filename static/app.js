/* ══════════════════════════════════════════
   Network Scanner — Dashboard JS
   Your devices guard
══════════════════════════════════════════ */

// ─── App State ───
let allDevices = [];
let allPending = [];
let renamingMac = null;
let activeSidePanel = "alerts"; // "alerts" | "settings" | "health"
let currentNetworkScope = "current";

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

        dropdown.innerHTML = networks.map(net => `
            <div class="network-item" onclick="selectNetwork('${escHtml(net.ssid)}')">
                <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                    <div>
                        <div style="font-weight:600; color:var(--text-1);">${escHtml(net.ssid)}</div>
                        <div style="font-size:0.75rem; color:var(--text-3);">${escHtml(net.security_type)}</div>
                    </div>
                    <div style="font-size:0.8rem; color:var(--blue-400);">
                        <i class="fa-solid fa-signal"></i> ${net.signal_strength}%
                    </div>
                </div>
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
            fetchJSON(`/api/status?scope=${currentNetworkScope}`),
            fetchJSON(`/api/devices?scope=${currentNetworkScope}`),
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

        // Fetch diagnostics for banner and health dot
        fetchDiagnostics();

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

    // Update scan status banner
    updateScanStatusBanner(status.scan_mode, status.subnet_warning);
}

function updateScanStatusBanner(scanMode, subnetWarning) {
    const banner = document.getElementById("scan-status-banner");
    const textEl = document.getElementById("scan-status-text");
    if (!banner || !textEl) return;

    banner.style.display = "flex";
    banner.style.flexDirection = "column";
    banner.style.alignItems = "flex-start";

    let baseHtml = "";
    let isError = false;

    if (scanMode === "ACTIVE_SCAN") {
        banner.style.background = "rgba(46, 204, 113, 0.1)";
        banner.style.borderColor = "rgba(46, 204, 113, 0.3)";
        banner.style.color = "var(--green)";
        baseHtml = '<div><i class="fa-solid fa-circle-check"></i> Live scanning active</div>';
    } else if (scanMode === "PASSIVE_ONLY") {
        banner.style.background = "rgba(241, 196, 15, 0.1)";
        banner.style.borderColor = "rgba(241, 196, 15, 0.3)";
        banner.style.color = "var(--orange)";
        baseHtml = '<div><i class="fa-solid fa-triangle-exclamation"></i> Passive mode — run as Administrator/sudo for full device discovery, some devices may not appear</div>';
    } else if (scanMode === "ARP_CACHE") {
        banner.style.background = "rgba(241, 196, 15, 0.1)";
        banner.style.borderColor = "rgba(241, 196, 15, 0.3)";
        banner.style.color = "var(--orange)";
        baseHtml = '<div><i class="fa-solid fa-triangle-exclamation"></i> Reading OS ARP cache every 30s — install Npcap/libpcap for live scanning</div>';
    } else if (scanMode === "SIMULATION") {
        banner.style.background = "rgba(230, 126, 34, 0.1)";
        banner.style.borderColor = "rgba(230, 126, 34, 0.3)";
        banner.style.color = "var(--orange)";
        baseHtml = '<div><i class="fa-solid fa-circle-info"></i> Simulation Mode Active — showing mock data, not your real network</div>';
    } else if (scanMode === "NPCAP_MISSING") {
        banner.style.background = "rgba(231, 76, 60, 0.1)";
        banner.style.borderColor = "rgba(231, 76, 60, 0.3)";
        banner.style.color = "#ff6b6b";
        baseHtml = '<div><i class="fa-solid fa-circle-xmark"></i> Npcap is not installed. Real network discovery is disabled. Install Npcap with \'WinPcap API-compatible Mode\' enabled, then restart the application.</div>';
        isError = true;
    } else {
        banner.style.display = "none";
        return;
    }

    if (subnetWarning && !isError) {
        // Prepend/append mismatch warning to the banner
        baseHtml += '<div style="margin-top: 0.35rem; font-size: 0.8rem; color: #ffbc42; font-weight: 600; display: flex; align-items: center; gap: 0.35rem;"><i class="fa-solid fa-triangle-exclamation"></i> Detected local IP and gateway IP are on different subnets — scan results may be incomplete, check for an active VPN</div>';
    }

    textEl.innerHTML = baseHtml;
}

function updateRootUserDisplay(rootUser) {
    if (!rootUser) return;
    const nameEl = document.getElementById("root-user-name-display");
    if (nameEl) {
        nameEl.textContent = rootUser.name || "Set up Admin";
    }
}

function refreshAgentConfigDisplay(status) {
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
// Global scope and segment filter state
let currentDeviceSegment = "all";

function changeNetworkScope(scope) {
    currentNetworkScope = scope;
    
    // Update button visual styles
    const btnCurrent = document.getElementById("scope-btn-current");
    const btnAll = document.getElementById("scope-btn-all");
    
    if (btnCurrent && btnAll) {
        if (scope === "current") {
            btnCurrent.style.background = "var(--blue-600)";
            btnCurrent.style.color = "white";
            btnAll.style.background = "transparent";
            btnAll.style.color = "var(--text-2)";
        } else {
            btnCurrent.style.background = "transparent";
            btnCurrent.style.color = "var(--text-2)";
            btnAll.style.background = "var(--blue-600)";
            btnAll.style.color = "white";
        }
    }
    
    refreshDashboard();
}

function setDeviceSegment(segment) {
    currentDeviceSegment = segment;
    
    // Update active class & styles on tabs
    document.querySelectorAll(".segment-tab").forEach(tab => {
        const matches = tab.getAttribute("data-segment") === segment;
        tab.classList.toggle("active", matches);
        if (matches) {
            tab.style.background = "var(--blue-600)";
            tab.style.color = "white";
            const badge = tab.querySelector(".segment-count");
            if (badge) badge.style.background = "rgba(255,255,255,0.2)";
        } else {
            tab.style.background = "var(--bg-card)";
            tab.style.color = "var(--text-2)";
            const badge = tab.querySelector(".segment-count");
            if (badge) badge.style.background = "rgba(255,255,255,0.1)";
        }
    });
    
    renderDevices();
}

function renderDevices() {
    const grid   = document.getElementById("devices-grid");
    const filter = (document.getElementById("device-filter")?.value || "").toLowerCase();

    // Calculate segment counts first based on allDevices (ignoring search filter for counts)
    const counts = { all: allDevices.length, pc: 0, phone: 0, tv: 0, iot: 0, router: 0, printer: 0 };
    allDevices.forEach(d => {
        const type = d.device_type || "unknown";
        if (counts[type] !== undefined) {
            counts[type]++;
        }
    });
    
    // Update count labels
    Object.keys(counts).forEach(k => {
        const el = document.getElementById(`count-${k}`);
        if (el) el.textContent = counts[k];
    });

    // Filter devices based on both segment and search text
    const filtered = allDevices.filter(d => {
        // Segment filter
        if (currentDeviceSegment !== "all") {
            const devType = d.device_type || "unknown";
            if (devType !== currentDeviceSegment) {
                return false;
            }
        }
        
        // Search filter
        const name = (d.friendly_name || d.hostname || "").toLowerCase();
        const ip   = (d.last_known_ip || "").toLowerCase();
        const mac  = (d.mac_address || "").toLowerCase();
        return name.includes(filter) || ip.includes(filter) || mac.includes(filter);
    });

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div style="grid-column:1/-1; padding:3rem; text-align:center; color:var(--text-3);">
                <i class="fa-solid fa-magnifying-glass" style="font-size:2rem;display:block;margin-bottom:0.75rem;"></i>
                No devices found in this segment.
            </div>`;
        return;
    }

    grid.innerHTML = filtered.map(d => buildDeviceCard(d)).join("");
}

function buildDeviceCard(d) {
    const name      = d.friendly_name || d.hostname || `Device-${(d.mac_address || "").slice(-5).replace(":", "")}`;
    const hostname  = d.hostname && d.hostname !== name ? d.hostname : "";
    const online    = d.is_online === 1;
    const vendor    = d.vendor || "Unknown";
    const osName    = d.operating_system || "";
    const confidence = (d.confidence_score > 0) ? d.confidence_score : null;

    const statusBadge = online
        ? `<span class="badge badge-green"><i class="fa-solid fa-circle-check"></i> Online</span>`
        : `<span class="badge badge-orange"><i class="fa-solid fa-circle-minus"></i> Offline</span>`;

    const confColor = confidence >= 85 ? "var(--green)" : confidence >= 60 ? "var(--orange)" : "#6b7280";
    const icon = guessDeviceIcon(d);
    const mac  = encodeURIComponent(d.mac_address);

    const osBadge = osName && osName !== "Unknown" ? `
        <div class="device-vendor" style="font-size:0.72rem; color:var(--text-2); margin-top:0.1rem;">
            <i class="fa-solid fa-microchip" style="color:#8b5cf6"></i> ${escHtml(osName)}
            ${confidence !== null ? `<span style="color:${confColor}; font-weight:600; margin-left:0.3rem;">${confidence}%</span>` : ""}
        </div>` : "";

    return `
    <div class="device-card" style="${!online ? "opacity: 0.7;" : ""}">
        <div class="device-card-top">
            <div class="device-icon-wrap">${icon}</div>
            <div class="device-online-dot" style="background-color: ${online ? "var(--green)" : "var(--text-3)"}"></div>
        </div>
        <div>
            <div class="device-name">${escHtml(name)}</div>
            ${hostname ? `<div class="device-hostname">${escHtml(hostname)}</div>` : ""}
            <div class="device-vendor" style="font-size:0.75rem; color:var(--blue-400); margin-top:0.1rem; font-weight:500;">
                <i class="fa-solid fa-building-circle-check"></i> ${escHtml(vendor)}
            </div>
            ${osBadge}
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
            ${currentNetworkScope === "all"
                ? `<div class="detail-row">
                       <span class="label">Subnet</span>
                       <span class="value" style="color: var(--blue-400); font-weight: 500;">${escHtml(d.network_hint || "—")}</span>
                   </div>`
                : ""
            }
            <div class="detail-row">
                <span class="label">First seen</span>
                <span class="value">${timeAgo(d.first_seen)}</span>
            </div>
            <div class="detail-row">
                <span class="label">Last seen</span>
                <span class="value">${timeAgo(d.last_seen)}</span>
            </div>
        </div>
        <div style="margin-top:0.25rem;">${statusBadge}</div>
        <div class="device-card-footer">
            <button class="btn btn-ghost btn-sm btn-block" onclick="openRenameModal('${mac}', '${escHtml(d.mac_address)}', '${escHtml(name)}')" title="Rename Device">
                <i class="fa-solid fa-pencil"></i> Rename
            </button>
        </div>
    </div>`;
}

function guessDeviceIcon(d) {
    const type = d.device_type || "unknown";
    if (type === "phone") return '<i class="fa-solid fa-mobile-screen"></i>';
    if (type === "pc") return '<i class="fa-solid fa-laptop"></i>';
    if (type === "tv") return '<i class="fa-solid fa-tv"></i>';
    if (type === "printer") return '<i class="fa-solid fa-print"></i>';
    if (type === "router") return '<i class="fa-solid fa-wifi"></i>';
    if (type === "iot") return '<i class="fa-solid fa-house-signal"></i>';

    const name = (d.friendly_name || d.hostname || "").toLowerCase();
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

// ─── Sidebar Panel Manager ───────────────
function _showPanel(panelId) {
    ["panel-alerts", "panel-settings", "panel-health"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.toggle("hidden", id !== panelId);
    });
}

// ─── Alerts Panel ────────────────────────
function showAlertsPanel() {
    activeSidePanel = "alerts";
    _showPanel("panel-alerts");
    fetchJSON("/api/alerts").then(renderAlerts);
}

function showSettingsPanel() {
    activeSidePanel = "settings";
    _showPanel("panel-settings");
}

function showHealthPanel() {
    activeSidePanel = "health";
    _showPanel("panel-health");
    fetchHealth();
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
    const btn = document.getElementById("btn-scan-now") || document.getElementById("btn-refresh-devices");
    const oldHtml = btn ? btn.innerHTML : "";
    if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
        btn.disabled = true;
    }
    try {
        const res = await postJSON("/api/scan/trigger");
        if (res && res.success) {
            toast(res.message || "Scan triggered.", "success");
            setTimeout(refreshDashboard, 2000);
        } else {
            toast((res && res.message) || "Scan failed.", "error");
        }
    } catch (e) {
        toast("Scan failed: server error.", "error");
    } finally {
        if (btn) {
            setTimeout(() => {
                btn.innerHTML = oldHtml;
                btn.disabled = false;
            }, 2000);
        }
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

// ─── Telegram Subscriber Registration ─────
async function subscribeTelegram() {
    const input = document.getElementById("inp-subscribe-chat-id");
    const chatId = input.value.trim();
    if (!chatId) {
        toast("Please enter a Telegram Chat ID.", "warning");
        return;
    }
    
    try {
        const res = await postJSON("/api/notify/telegram/subscribe", { chat_id: chatId });
        if (res.success) {
            toast(res.message || "Subscribed successfully!", "success");
            input.value = "";
            refreshDashboard();
        } else {
            toast(res.message || "Subscription failed.", "error");
        }
    } catch (e) {
        toast("Failed to register subscription.", "error");
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

// ─── About Modal ─────────────────────────
function showAboutModal() {
    document.getElementById("about-modal").classList.remove("hidden");
}

function closeAboutModal() {
    document.getElementById("about-modal").classList.add("hidden");
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
    const btn = document.getElementById("btn-test-webhook");
    const resultEl = document.getElementById("webhook-test-result");
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Testing…'; }
    if (resultEl) resultEl.textContent = "";
    try {
        const res = await postJSON("/api/webhook/test");
        if (res.success) {
            toast("Webhook test sent successfully!", "success");
            if (resultEl) { resultEl.textContent = "✓ " + (res.message || "Sent"); resultEl.style.color = "var(--green)"; }
        } else {
            toast(res.message || "Webhook test failed.", "warning");
            if (resultEl) { resultEl.textContent = "✗ " + (res.message || "Failed"); resultEl.style.color = "#ef4444"; }
        }
    } catch(e) {
        toast("Webhook test error: " + e.message, "error");
        if (resultEl) { resultEl.textContent = "✗ Network error"; resultEl.style.color = "#ef4444"; }
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Test'; }
    }
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

    const res = await patchJSON(`/api/devices/${encodeURIComponent(renamingMac)}`, { friendly_name: name });
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
function getSessionToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
}

async function postJSON(url, body = {}) {
    const res = await fetch(url, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "X-Session-Token": getSessionToken()
        },
        body: JSON.stringify(body)
    });
    return res.json();
}

async function patchJSON(url, body = {}) {
    const res = await fetch(url, {
        method: "PATCH",
        headers: { 
            "Content-Type": "application/json",
            "X-Session-Token": getSessionToken()
        },
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

// ─── Diagnostics Banner (Phase 5) ────────
async function fetchDiagnostics() {
    try {
        const data = await fetchJSON("/api/diagnostics");
        renderDiagnosticsBanner(data);
        // Update health dot indicator
        const healthDot = document.getElementById("health-dot");
        if (healthDot) {
            const hasError = Object.values(data.health || {}).some(h => h.status === "error");
            healthDot.classList.toggle("hidden", !hasError);
        }
    } catch(e) {
        console.warn("Diagnostics fetch failed:", e);
    }
}

function renderDiagnosticsBanner(data) {
    const banner = document.getElementById("diagnostics-banner");
    const inner  = document.getElementById("diagnostics-inner");
    const modeLabel = document.getElementById("diag-mode-label");
    const liveStats = document.getElementById("diag-live-stats");
    const indicators = document.getElementById("diag-indicators");
    if (!banner || !data) return;

    const scan = data.scan || {};
    const mode = scan.mode || "";

    const modeConfig = {
        ACTIVE_SCAN:  { icon: "fa-circle-check", label: "Active Scan",    bg: "rgba(16,185,129,0.08)",  border: "rgba(16,185,129,0.3)",  color: "#10b981" },
        PASSIVE_ONLY: { icon: "fa-eye",           label: "Passive Only",   bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.3)",  color: "#f59e0b" },
        ARP_CACHE:    { icon: "fa-database",      label: "ARP Cache Only", bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.3)",  color: "#f59e0b" },
        SIMULATION:   { icon: "fa-flask",         label: "Simulation",     bg: "rgba(139,92,246,0.08)",  border: "rgba(139,92,246,0.3)",  color: "#8b5cf6" },
        NPCAP_MISSING:{ icon: "fa-circle-xmark",  label: "Npcap Missing",  bg: "rgba(239,68,68,0.08)",   border: "rgba(239,68,68,0.3)",   color: "#ef4444" },
    };
    const cfg = modeConfig[mode] || { icon: "fa-circle-info", label: mode || "Unknown", bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.3)", color: "#94a3b8" };

    if (inner) { inner.style.background = cfg.bg; inner.style.borderColor = cfg.border; }

    if (modeLabel) {
        modeLabel.style.color = cfg.color;
        modeLabel.innerHTML = `<i class="fa-solid ${cfg.icon}"></i> Scan Mode: <strong>${cfg.label}</strong>`;
    }

    if (liveStats) {
        liveStats.style.color = cfg.color;
        const iface  = scan.current_interface || "—";
        const subnet = scan.subnet || "—";
        const gw     = scan.gateway || "—";
        const pkts   = (scan.packets_captured || 0).toLocaleString();
        const arp    = (scan.arp_requests_sent || 0).toLocaleString();
        const last   = scan.last_scan_time !== "Never" ? scan.last_scan_time : "Never";
        liveStats.innerHTML = `
            <span title="Interface"><i class="fa-solid fa-network-wired"></i> ${escHtml(iface)}</span>
            <span title="Subnet"><i class="fa-solid fa-sitemap"></i> ${escHtml(subnet)}</span>
            <span title="Gateway"><i class="fa-solid fa-route"></i> ${escHtml(gw)}</span>
            <span title="Packets captured"><i class="fa-solid fa-wave-square"></i> ${pkts} pkts</span>
            <span title="ARP sent"><i class="fa-solid fa-broadcast-tower"></i> ${arp} ARP</span>
            <span title="Last scan"><i class="fa-regular fa-clock"></i> ${escHtml(last)}</span>
        `;
    }

    if (indicators) {
        const pillItems = [
            { key: "npcap",             label: "Npcap",          icon: "fa-plug" },
            { key: "packet_capture",    label: "Packet Capture", icon: "fa-wave-square" },
            { key: "passive_discovery", label: "Passive",        icon: "fa-eye" },
            { key: "active_arp",        label: "Active ARP",     icon: "fa-broadcast-tower" },
        ];
        indicators.innerHTML = pillItems.map(p => {
            const ok  = scan[p.key];
            const col = ok ? "#10b981" : "#ef4444";
            const icn = ok ? "fa-circle-check" : "fa-circle-xmark";
            const title = (p.key === "active_arp" && !ok && scan.active_arp_reason)
                ? escHtml(scan.active_arp_reason) : "";
            return `<div style="padding:0.4rem 0.75rem; display:flex; align-items:center; gap:0.3rem; font-size:0.72rem; font-weight:600; color:${col}; border-right:1px solid rgba(255,255,255,0.06);" title="${title}">
                <i class="fa-solid ${icn}"></i>&nbsp;<i class="fa-solid ${p.icon}" style="opacity:0.7"></i>&nbsp;${p.label}
            </div>`;
        }).join("");
    }

    banner.style.display = "block";
}

// ─── Health Dashboard (Phase 13) ─────────
async function fetchHealth() {
    const body = document.getElementById("health-panel-body");
    if (body) body.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-circle-notch fa-spin"></i> Checking…</div>';
    try {
        const data = await fetchJSON("/api/diagnostics");
        renderHealth(data, body);
    } catch(e) {
        if (body) body.innerHTML = '<div class="empty-msg" style="color:#ef4444">Failed to load health data.</div>';
    }
}

function renderHealth(data, body) {
    if (!body || !data) return;
    const health = data.health || {};
    const labels = {
        npcap:     { icon: "fa-plug",             label: "Npcap Driver"     },
        scapy:     { icon: "fa-code",             label: "Scapy Library"    },
        database:  { icon: "fa-database",         label: "Database"         },
        internet:  { icon: "fa-globe",            label: "Internet"         },
        telegram:  { icon: "fa-brands fa-telegram", label: "Telegram Bot"   },
        webhook:   { icon: "fa-paper-plane",      label: "Webhook"          },
        discovery: { icon: "fa-broadcast-tower",  label: "Discovery Engine" },
        interface: { icon: "fa-network-wired",    label: "Network Interface"},
        gateway:   { icon: "fa-route",            label: "Gateway"          },
    };
    const colors = { ok: "#10b981", warn: "#f59e0b", error: "#ef4444" };
    const icons  = { ok: "fa-circle-check", warn: "fa-triangle-exclamation", error: "fa-circle-xmark" };

    body.innerHTML = Object.entries(health).map(([k, v]) => {
        const meta = labels[k] || { icon: "fa-circle-info", label: k };
        const col  = colors[v.status] || "#94a3b8";
        const icn  = icons[v.status]  || "fa-circle-info";
        return `
        <div style="display:flex; align-items:center; justify-content:space-between; padding:0.5rem 0; border-bottom:1px solid var(--border); gap:0.5rem;">
            <span style="display:flex; align-items:center; gap:0.4rem; font-size:0.8rem; color:var(--text-2); flex:1;">
                <i class="fa-solid ${meta.icon}" style="width:1rem; text-align:center; color:${col}"></i>
                ${meta.label}
            </span>
            <span style="display:flex; align-items:center; gap:0.3rem; font-size:0.75rem; font-weight:600; color:${col}; text-align:right;">
                <i class="fa-solid ${icn}"></i>
                ${escHtml(v.detail || v.status)}
            </span>
        </div>`;
    }).join("");
}
