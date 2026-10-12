/**
 * PhishGuard - Real-Time Phishing Detection & Analysis
 * Client-Side Application Logic (Zero Mock Data)
 */

document.addEventListener("DOMContentLoaded", () => {
    // ------------------------------------------------------------------------
    // State Management
    // ------------------------------------------------------------------------
    let allHistoryRecords = [];
    let currentStats = {
        total_scans: 0,
        url_scans: 0,
        message_scans: 0,
        low_risk: 0,
        suspicious: 0,
        high_risk: 0,
        critical: 0
    };

    // ------------------------------------------------------------------------
    // DOM Element References
    // ------------------------------------------------------------------------
    const navItems = document.querySelectorAll(".nav-item");
    const viewPanels = document.querySelectorAll(".view-panel");

    // Metric Displays
    const statTotalScans = document.getElementById("statTotalScans");
    const statUrlScans = document.getElementById("statUrlScans");
    const statMessageScans = document.getElementById("statMessageScans");
    const statLowRisk = document.getElementById("statLowRisk");
    const statSuspicious = document.getElementById("statSuspicious");
    const statHighRisk = document.getElementById("statHighRisk");
    const statCritical = document.getElementById("statCritical");
    const navHistoryCount = document.getElementById("navHistoryCount");

    // Action Launchers on Dashboard
    const btnRefreshStats = document.getElementById("btnRefreshStats");
    const btnLaunchUrlScan = document.getElementById("btnLaunchUrlScan");
    const btnLaunchMessageScan = document.getElementById("btnLaunchMessageScan");
    const btnViewAllHistory = document.getElementById("btnViewAllHistory");
    const dashboardRecentTbody = document.getElementById("dashboardRecentTbody");

    // URL Scanner Elements
    const urlScanForm = document.getElementById("urlScanForm");
    const urlInput = document.getElementById("urlInput");
    const btnScanUrl = document.getElementById("btnScanUrl");
    const urlResultContainer = document.getElementById("urlResultContainer");

    // Message Analyzer Elements
    const messageScanForm = document.getElementById("messageScanForm");
    const messageInput = document.getElementById("messageInput");
    const messageCharCounter = document.getElementById("messageCharCounter");
    const btnAnalyzeMessage = document.getElementById("btnAnalyzeMessage");
    const messageResultContainer = document.getElementById("messageResultContainer");

    // History Table & Controls
    const historyTbody = document.getElementById("historyTbody");
    const btnReloadHistory = document.getElementById("btnReloadHistory");
    const btnClearHistory = document.getElementById("btnClearHistory");
    const filterType = document.getElementById("filterType");
    const filterRisk = document.getElementById("filterRisk");
    const historySearchInput = document.getElementById("historySearchInput");

    // Detail Modal Elements
    const detailModal = document.getElementById("detailModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalTypeBadge = document.getElementById("modalTypeBadge");
    const modalBody = document.getElementById("modalBody");
    const btnCloseModal = document.getElementById("btnCloseModal");
    const btnDismissModal = document.getElementById("btnDismissModal");

    // System Clock
    const systemClock = document.getElementById("systemClock");

    // ------------------------------------------------------------------------
    // Helper Utilities
    // ------------------------------------------------------------------------
    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function showToast(message, type = "success") {
        const container = document.getElementById("toastContainer");
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        
        const iconSvg = type === "success" 
            ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`
            : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

        toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    function formatTimestamp(isoStr) {
        if (!isoStr) return "N/A";
        try {
            const date = new Date(isoStr);
            if (isNaN(date.getTime())) return isoStr;
            return date.toISOString().replace("T", " ").substring(0, 19);
        } catch {
            return isoStr;
        }
    }

    function getRiskClass(level) {
        const normalized = String(level || "").toLowerCase();
        if (normalized.includes("critical")) return "critical";
        if (normalized.includes("high")) return "high";
        if (normalized.includes("suspicious")) return "suspicious";
        return "low";
    }

    function getRiskColorHex(level) {
        const cls = getRiskClass(level);
        if (cls === "critical") return "#ef4444";
        if (cls === "high") return "#f97316";
        if (cls === "suspicious") return "#f59e0b";
        return "#10b981";
    }

    // ------------------------------------------------------------------------
    // Clock & Navigation
    // ------------------------------------------------------------------------
    function updateClock() {
        const now = new Date();
        systemClock.textContent = now.toUTCString().replace("GMT", "UTC");
    }
    setInterval(updateClock, 1000);
    updateClock();

    function switchTab(targetTabId) {
        viewPanels.forEach(panel => {
            if (panel.id === targetTabId) {
                panel.classList.add("active");
            } else {
                panel.classList.remove("active");
            }
        });

        navItems.forEach(item => {
            if (item.getAttribute("data-tab") === targetTabId) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Trigger refresh if navigating to history or dashboard
        if (targetTabId === "dashboard-view" || targetTabId === "history-view") {
            loadScanHistory();
        }
    }

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const target = item.getAttribute("data-tab");
            switchTab(target);
        });
    });

    if (btnLaunchUrlScan) {
        btnLaunchUrlScan.addEventListener("click", () => switchTab("url-view"));
    }
    if (btnLaunchMessageScan) {
        btnLaunchMessageScan.addEventListener("click", () => switchTab("message-view"));
    }
    if (btnViewAllHistory) {
        btnViewAllHistory.addEventListener("click", () => switchTab("history-view"));
    }
    if (btnRefreshStats) {
        btnRefreshStats.addEventListener("click", () => {
            loadScanHistory();
            showToast("Telemetry synced with SQLite database.");
        });
    }

    // ------------------------------------------------------------------------
    // Metrics Rendering
    // ------------------------------------------------------------------------
    function updateDashboardMetrics(stats) {
        if (!stats) return;
        currentStats = stats;

        statTotalScans.textContent = stats.total_scans ?? 0;
        statUrlScans.textContent = stats.url_scans ?? 0;
        statMessageScans.textContent = stats.message_scans ?? 0;
        statLowRisk.textContent = stats.low_risk ?? 0;
        statSuspicious.textContent = stats.suspicious ?? 0;
        statHighRisk.textContent = stats.high_risk ?? 0;
        statCritical.textContent = stats.critical ?? 0;

        navHistoryCount.textContent = stats.total_scans ?? 0;
    }

    // ------------------------------------------------------------------------
    // API: Fetch Scan History & Compute Telemetry
    // ------------------------------------------------------------------------
    async function loadScanHistory() {
        try {
            const response = await fetch("/api/history?limit=100", {
                method: "GET",
                headers: { "Accept": "application/json" }
            });

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                allHistoryRecords = data.history || [];
                updateDashboardMetrics(data.stats);
                renderDashboardRecentTable(allHistoryRecords.slice(0, 5));
                renderHistoryTable();
            }
        } catch (err) {
            console.error("Error loading scan history:", err);
            dashboardRecentTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-6">
                        Failed to retrieve records from SQLite backend.
                    </td>
                </tr>
            `;
            historyTbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center text-muted py-8">
                        Database connection unavailable. Check server logs.
                    </td>
                </tr>
            `;
        }
    }

    // ------------------------------------------------------------------------
    // Table Renderers
    // ------------------------------------------------------------------------
    function renderDashboardRecentTable(records) {
        if (!records || records.length === 0) {
            dashboardRecentTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-6">
                        No scan telemetry recorded yet. Perform a scan to generate data.
                    </td>
                </tr>
            `;
            return;
        }

        dashboardRecentTbody.innerHTML = records.map(record => {
            const riskCls = getRiskClass(record.risk_level);
            const indicatorCount = Array.isArray(record.indicators) ? record.indicators.length : 0;
            const typeCls = record.scan_type === "url" ? "url" : "message";

            return `
                <tr>
                    <td class="text-mono">${escapeHtml(formatTimestamp(record.timestamp))}</td>
                    <td><span class="table-type-badge ${typeCls}">${escapeHtml(record.scan_type)}</span></td>
                    <td class="table-target-cell" title="${escapeHtml(record.target)}">${escapeHtml(record.target)}</td>
                    <td class="text-mono font-bold">${record.score} / 100</td>
                    <td><span class="metric-badge-risk ${riskCls}">${escapeHtml(record.risk_level)}</span></td>
                    <td>
                        <span class="text-muted text-mono">${indicatorCount} indicator(s)</span>
                    </td>
                </tr>
            `;
        }).join("");
    }

    function renderHistoryTable() {
        const typeVal = filterType.value;
        const riskVal = filterRisk.value;
        const searchVal = (historySearchInput.value || "").trim().toLowerCase();

        const filtered = allHistoryRecords.filter(r => {
            if (typeVal !== "all" && r.scan_type !== typeVal) return false;
            if (riskVal !== "all" && r.risk_level !== riskVal) return false;
            if (searchVal && !String(r.target || "").toLowerCase().includes(searchVal)) return false;
            return true;
        });

        if (filtered.length === 0) {
            historyTbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center text-muted py-8">
                        ${allHistoryRecords.length === 0 ? "No scan history records found in SQLite database." : "No records match the active filter criteria."}
                    </td>
                </tr>
            `;
            return;
        }

        historyTbody.innerHTML = filtered.map(record => {
            const riskCls = getRiskClass(record.risk_level);
            const indicatorCount = Array.isArray(record.indicators) ? record.indicators.length : 0;
            const typeCls = record.scan_type === "url" ? "url" : "message";

            return `
                <tr data-record-id="${record.id}">
                    <td class="text-mono text-muted">#${record.id}</td>
                    <td class="text-mono">${escapeHtml(formatTimestamp(record.timestamp))}</td>
                    <td><span class="table-type-badge ${typeCls}">${escapeHtml(record.scan_type)}</span></td>
                    <td class="table-target-cell" title="${escapeHtml(record.target)}">${escapeHtml(record.target)}</td>
                    <td class="text-mono font-bold">${record.score}/100</td>
                    <td><span class="metric-badge-risk ${riskCls}">${escapeHtml(record.risk_level)}</span></td>
                    <td><span class="text-muted text-mono">${indicatorCount} detected</span></td>
                    <td>
                        <button class="btn btn-sm btn-secondary btn-inspect" data-id="${record.id}">
                            View Details
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

        // Attach modal inspection listeners
        document.querySelectorAll(".btn-inspect").forEach(btn => {
            btn.addEventListener("click", () => {
                const id = parseInt(btn.getAttribute("data-id"), 10);
                const rec = allHistoryRecords.find(item => item.id === id);
                if (rec) openDetailModal(rec);
            });
        });
    }

    filterType.addEventListener("change", renderHistoryTable);
    filterRisk.addEventListener("change", renderHistoryTable);
    historySearchInput.addEventListener("input", renderHistoryTable);

    btnReloadHistory.addEventListener("click", () => {
        loadScanHistory();
        showToast("History refreshed from SQLite.");
    });

    // ------------------------------------------------------------------------
    // API: Clear Scan History (DELETE /api/history)
    // ------------------------------------------------------------------------
    btnClearHistory.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to permanently clear all scan history from the SQLite database?")) {
            return;
        }

        try {
            btnClearHistory.disabled = true;
            const response = await fetch("/api/history", {
                method: "DELETE",
                headers: { "Accept": "application/json" }
            });

            if (!response.ok) {
                throw new Error(`HTTP Error ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                allHistoryRecords = [];
                updateDashboardMetrics(data.stats);
                renderDashboardRecentTable([]);
                renderHistoryTable();
                showToast(data.message || "History cleared successfully.");
            } else {
                showToast(data.error || "Failed to clear history.", "error");
            }
        } catch (err) {
            console.error("Failed to delete history:", err);
            showToast("Failed to connect to server.", "error");
        } finally {
            btnClearHistory.disabled = false;
        }
    });

    // ------------------------------------------------------------------------
    // Modal Inspection Logic
    // ------------------------------------------------------------------------
    function openDetailModal(record) {
        modalTitle.textContent = `Scan Record #${record.id} Evaluation`;
        modalTypeBadge.textContent = record.scan_type.toUpperCase();
        modalTypeBadge.className = `modal-badge ${record.scan_type}`;

        const riskCls = getRiskClass(record.risk_level);
        const indicators = Array.isArray(record.indicators) ? record.indicators : [];

        let indicatorsHtml = "";
        if (indicators.length === 0) {
            indicatorsHtml = `
                <div class="no-indicators-box">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                        <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                    <span>Zero high-risk heuristic triggers detected for this evaluation.</span>
                </div>
            `;
        } else {
            indicatorsHtml = indicators.map(ind => `
                <div class="indicator-card">
                    <span class="indicator-severity-badge ${ind.severity || 'low'}">${escapeHtml(ind.severity || 'Info')}</span>
                    <div class="indicator-content">
                        <div class="indicator-title-row">
                            <span class="indicator-title">${escapeHtml(ind.title || ind.id)}</span>
                            <span class="indicator-weight-tag">+${ind.weight ?? 0} pts</span>
                        </div>
                        <p class="indicator-desc">${escapeHtml(ind.description || "")}</p>
                    </div>
                </div>
            `).join("");
        }

        modalBody.innerHTML = `
            <div style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div>
                        <span class="risk-level-pill ${riskCls}">${escapeHtml(record.risk_level)}</span>
                        <span class="text-mono text-muted" style="margin-left: 10px; font-size: 0.9rem;">
                            Score: <strong>${record.score}</strong> / 100
                        </span>
                    </div>
                    <span class="text-mono text-muted text-xs">${escapeHtml(formatTimestamp(record.timestamp))}</span>
                </div>

                <div class="target-display-card" style="padding: 14px 18px; margin-bottom: 16px;">
                    <div class="target-badge-label" style="margin-bottom: 6px;">Evaluated Target</div>
                    <div class="target-value-box">${escapeHtml(record.target)}</div>
                </div>

                <div class="section-subtitle">Analytical Explanation</div>
                <div class="explanation-text" style="margin-bottom: 20px;">
                    ${escapeHtml(record.explanation)}
                </div>

                <div class="section-subtitle">Detected Heuristic Indicators (${indicators.length})</div>
                <div class="indicators-grid">
                    ${indicatorsHtml}
                </div>
            </div>
        `;

        detailModal.classList.remove("hidden");
    }

    btnCloseModal.addEventListener("click", () => detailModal.classList.add("hidden"));
    btnDismissModal.addEventListener("click", () => detailModal.classList.add("hidden"));
    detailModal.addEventListener("click", (e) => {
        if (e.target === detailModal) detailModal.classList.add("hidden");
    });

    // ------------------------------------------------------------------------
    // Shared Result Panel Generator
    // ------------------------------------------------------------------------
    function createResultCardMarkup(data, scanType) {
        const riskCls = getRiskClass(data.risk_level);
        const colorHex = getRiskColorHex(data.risk_level);
        const radius = 36;
        const circumference = 2 * Math.PI * radius;
        const strokeDashoffset = circumference - (data.score / 100) * circumference;

        const indicators = Array.isArray(data.indicators) ? data.indicators : [];

        let indicatorsHtml = "";
        if (indicators.length === 0) {
            indicatorsHtml = `
                <div class="no-indicators-box">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                        <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                    <span>No known phishing indicators or heuristic triggers were identified in this sample.</span>
                </div>
            `;
        } else {
            indicatorsHtml = indicators.map(ind => `
                <div class="indicator-card">
                    <span class="indicator-severity-badge ${ind.severity || 'low'}">${escapeHtml(ind.severity || 'Info')}</span>
                    <div class="indicator-content">
                        <div class="indicator-title-row">
                            <span class="indicator-title">${escapeHtml(ind.title || ind.id)}</span>
                            <span class="indicator-weight-tag">+${ind.weight ?? 0} pts</span>
                        </div>
                        <p class="indicator-desc">${escapeHtml(ind.description || "")}</p>
                    </div>
                </div>
            `).join("");
        }

        const targetLabel = scanType === "url" ? "Target URL (Exact Input)" : "Evaluated Message Content";

        return `
            <div class="result-card risk-${riskCls}">
                <!-- Hero Score & Status -->
                <div class="result-hero">
                    <div class="result-hero-left">
                        <div class="score-circle-wrapper">
                            <svg class="score-circle-svg" width="90" height="90" viewBox="0 0 90 90">
                                <circle class="score-circle-bg" cx="45" cy="45" r="${radius}"></circle>
                                <circle class="score-circle-progress" cx="45" cy="45" r="${radius}"
                                    stroke="${colorHex}"
                                    stroke-dasharray="${circumference}"
                                    stroke-dashoffset="${strokeDashoffset}"></circle>
                            </svg>
                            <div class="score-circle-text">
                                <span class="score-number">${data.score}</span>
                                <span class="score-unit">/100</span>
                            </div>
                        </div>

                        <div class="result-level-badge-wrap">
                            <span class="risk-level-pill ${riskCls}">${escapeHtml(data.risk_level)}</span>
                            <span class="scan-timestamp-info">Scanned: ${escapeHtml(formatTimestamp(data.timestamp))}</span>
                        </div>
                    </div>
                </div>

                <!-- Exact Target Display (CRITICAL REQUIREMENT) -->
                <div class="target-display-card">
                    <div class="target-label-row">
                        <span class="target-badge-label">${targetLabel}</span>
                    </div>
                    <div class="target-value-box">${escapeHtml(data.target)}</div>
                </div>

                <!-- Explanation -->
                <div class="result-explanation-section">
                    <div class="section-subtitle">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="16" x2="12" y2="12"></line>
                            <line x1="12" y1="8" x2="12.01" y2="8"></line>
                        </svg>
                        <span>Detection Summary &amp; Explanation</span>
                    </div>
                    <p class="explanation-text">${escapeHtml(data.explanation)}</p>
                </div>

                <!-- Indicators -->
                <div class="result-indicators-section">
                    <div class="section-subtitle">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                            <polyline points="2 17 12 22 22 17"></polyline>
                            <polyline points="2 12 12 17 22 12"></polyline>
                        </svg>
                        <span>Triggered Heuristic Indicators (${indicators.length})</span>
                    </div>
                    <div class="indicators-grid">
                        ${indicatorsHtml}
                    </div>
                </div>
            </div>
        `;
    }

    // ------------------------------------------------------------------------
    // URL SCANNER: Real-Time Flow
    // ------------------------------------------------------------------------
    urlScanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const rawUrl = (urlInput.value || "").trim();

        if (!rawUrl) {
            showToast("Please enter a valid URL to scan.", "error");
            urlInput.focus();
            return;
        }

        try {
            // Set loading state
            btnScanUrl.disabled = true;
            btnScanUrl.classList.add("loading");

            const response = await fetch("/api/scan-url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({ url: rawUrl })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                showToast(data.error || `Scan failed with status ${response.status}`, "error");
                return;
            }

            // Immediately render the analysis results
            urlResultContainer.innerHTML = createResultCardMarkup(data.data, "url");
            urlResultContainer.classList.remove("hidden");
            urlResultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });

            // Immediately update database statistics
            if (data.stats) {
                updateDashboardMetrics(data.stats);
            }

            // Immediately update scan history in background
            loadScanHistory();

            showToast(`Scan complete: ${data.data.risk_level} (${data.data.score}/100)`);
        } catch (err) {
            console.error("Scan URL Error:", err);
            showToast("Network error or server unreachable.", "error");
        } finally {
            btnScanUrl.disabled = false;
            btnScanUrl.classList.remove("loading");
        }
    });

    // Preset Pill Clicks for URL
    document.querySelectorAll(".preset-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            const presetUrl = pill.getAttribute("data-target");
            urlInput.value = presetUrl;
            // Automatically trigger the scan
            btnScanUrl.click();
        });
    });

    // ------------------------------------------------------------------------
    // MESSAGE ANALYZER: Real-Time Flow
    // ------------------------------------------------------------------------
    messageInput.addEventListener("input", () => {
        const len = messageInput.value.length;
        messageCharCounter.textContent = `${len.toLocaleString()} / 10,000 characters`;
    });

    messageScanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const rawMessage = (messageInput.value || "").trim();

        if (!rawMessage) {
            showToast("Please paste message content to analyze.", "error");
            messageInput.focus();
            return;
        }

        try {
            btnAnalyzeMessage.disabled = true;
            btnAnalyzeMessage.classList.add("loading");

            const response = await fetch("/api/analyze-message", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({ message: rawMessage })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                showToast(data.error || `Analysis failed with status ${response.status}`, "error");
                return;
            }

            // Immediately render results
            messageResultContainer.innerHTML = createResultCardMarkup(data.data, "message");
            messageResultContainer.classList.remove("hidden");
            messageResultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });

            // Immediately update dashboard metrics
            if (data.stats) {
                updateDashboardMetrics(data.stats);
            }

            // Immediately update scan history
            loadScanHistory();

            showToast(`Analysis complete: ${data.data.risk_level} (${data.data.score}/100)`);
        } catch (err) {
            console.error("Analyze Message Error:", err);
            showToast("Network error or server unreachable.", "error");
        } finally {
            btnAnalyzeMessage.disabled = false;
            btnAnalyzeMessage.classList.remove("loading");
        }
    });

    // Sample Message Lures
    const sampleLures = {
        benign: "Hi team, please find the meeting agenda for tomorrow's standup attached. Let me know if you need to add any discussion topics before 9 AM.",
        urgent_account: "URGENT ACTION REQUIRED: Your account has been suspended due to unauthorized login attempts. You must verify your credentials and enter your password within 24 hours or your access will be terminated permanently: http://verify-secure-login.xyz/update",
        prize_lottery: "CONGRATULATIONS! You have won the $5,000 cash prize in our exclusive giveaway. To claim your cash prize and free gift card, enter your bank account details immediately before the reward expires today!",
        delivery_scam: "USPS Notification: Your package could not be delivered due to an unpaid shipping fee of $2.30. Please confirm your shipping address and pay the fee immediately to reschedule delivery: https://usps-tracking-parcel.xyz/claim"
    };

    document.querySelectorAll(".preset-msg-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            const key = pill.getAttribute("data-sample");
            if (sampleLures[key]) {
                messageInput.value = sampleLures[key];
                messageCharCounter.textContent = `${sampleLures[key].length.toLocaleString()} / 10,000 characters`;
                // Automatically analyze
                btnAnalyzeMessage.click();
            }
        });
    });

    // ------------------------------------------------------------------------
    // Initial Load
    // ------------------------------------------------------------------------
    loadScanHistory();
});
