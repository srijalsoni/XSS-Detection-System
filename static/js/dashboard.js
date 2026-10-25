// Security Monitoring Dashboard UI Orchestration
// Strictly adheres to CSP: No eval, no inline handlers, no innerHTML for untrusted data.

document.addEventListener("DOMContentLoaded", () => {
    let currentTimeRange = "all";
    let chartInstances = {};

    // Elements
    const valTotal = document.getElementById("val-total-events");
    const valCritical = document.getElementById("val-critical-events");
    const valHigh = document.getElementById("val-high-events");
    const valBlocked = document.getElementById("val-blocked-events");
    const lastUpdatedText = document.getElementById("last-updated-text");
    const tbody = document.getElementById("telemetry-tbody");
    const emptyMsg = document.getElementById("empty-table-msg");

    // Color Palettes
    const RISK_COLORS = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#38bdf8"
    };

    const ACTION_COLORS = {
        "BLOCKED": "#8b5cf6",
        "REJECTED": "#ef4444",
        "SAFE_RENDERED": "#22c55e",
        "LOGGED": "#6366f1"
    };

    // Initialize Time Filters
    const filterButtons = document.querySelectorAll(".filter-btn");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            filterButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentTimeRange = btn.getAttribute("data-range");
            fetchDashboardData();
        });
    });

    const refreshBtn = document.getElementById("btn-refresh");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => fetchDashboardData());
    }

    // Helper: Safely clear an element
    function clearElement(el) {
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }

    // Main fetch orchestrator
    async function fetchDashboardData() {
        const queryParam = `?time_range=${encodeURIComponent(currentTimeRange)}`;

        try {
            // Concurrent API fetching
            const [
                summaryRes,
                riskRes,
                actionsRes,
                rulesRes,
                endpointsRes,
                timelineRes,
                recentRes
            ] = await Promise.all([
                fetch(`/api/security/summary${queryParam}`),
                fetch(`/api/security/risk-distribution${queryParam}`),
                fetch(`/api/security/actions${queryParam}`),
                fetch(`/api/security/rules${queryParam}`),
                fetch(`/api/security/endpoints${queryParam}`),
                fetch(`/api/security/timeline${queryParam}`),
                fetch(`/api/security/recent${queryParam}`)
            ]);

            if (summaryRes.ok) updateSummary(await summaryRes.json());
            if (riskRes.ok) renderRiskChart(await riskRes.json());
            if (actionsRes.ok) renderActionsChart(await actionsRes.json());
            if (rulesRes.ok) renderRulesChart(await rulesRes.json());
            if (endpointsRes.ok) renderEndpointsChart(await endpointsRes.json());
            if (timelineRes.ok) renderTimelineChart(await timelineRes.json());
            if (recentRes.ok) renderRecentEvents(await recentRes.json());

            if (lastUpdatedText) {
                lastUpdatedText.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
            }
        } catch (err) {
            console.error("Failed to load security telemetry:", err);
        }
    }

    // Update Summary Metric Cards
    function updateSummary(data) {
        if (valTotal) valTotal.textContent = data.total_events || 0;
        if (valCritical) valCritical.textContent = data.critical_events || 0;
        if (valHigh) valHigh.textContent = data.high_risk_events || 0;
        if (valBlocked) valBlocked.textContent = data.blocked_events || 0;
    }

    // Render Timeline Chart (Line)
    function renderTimelineChart(data) {
        const ctx = document.getElementById("chart-timeline");
        if (!ctx) return;

        if (chartInstances.timeline) chartInstances.timeline.destroy();

        chartInstances.timeline = new Chart(ctx, {
            type: "line",
            data: {
                labels: data.labels && data.labels.length ? data.labels : ["No Data"],
                datasets: [{
                    label: "Events",
                    data: data.counts && data.counts.length ? data.counts : [0],
                    borderColor: "#0284c7",
                    backgroundColor: "rgba(2, 132, 199, 0.1)",
                    fill: true,
                    tension: 0.3,
                    pointRadius: 4,
                    pointBackgroundColor: "#0284c7"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }

    // Render Risk Distribution Chart (Doughnut)
    function renderRiskChart(data) {
        const ctx = document.getElementById("chart-risk");
        if (!ctx) return;

        if (chartInstances.risk) chartInstances.risk.destroy();

        const labels = data.labels || [];
        const counts = data.counts || [];
        const backgroundColors = labels.map(l => RISK_COLORS[l] || "#94a3b8");

        chartInstances.risk = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors,
                    borderWidth: 2,
                    borderColor: "#ffffff"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right" }
                }
            }
        });
    }

    // Render Response Actions Chart (Bar)
    function renderActionsChart(data) {
        const ctx = document.getElementById("chart-actions");
        if (!ctx) return;

        if (chartInstances.actions) chartInstances.actions.destroy();

        const labels = data.labels || [];
        const counts = data.counts || [];
        const backgroundColors = labels.map(l => ACTION_COLORS[l] || "#64748b");

        chartInstances.actions = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }

    // Render Detection Rules Chart (Horizontal Bar)
    function renderRulesChart(data) {
        const ctx = document.getElementById("chart-rules");
        if (!ctx) return;

        if (chartInstances.rules) chartInstances.rules.destroy();

        chartInstances.rules = new Chart(ctx, {
            type: "bar",
            data: {
                labels: data.labels || [],
                datasets: [{
                    data: data.counts || [],
                    backgroundColor: "#f59e0b",
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }

    // Render Targeted Endpoints Chart (Doughnut)
    function renderEndpointsChart(data) {
        const ctx = document.getElementById("chart-endpoints");
        if (!ctx) return;

        if (chartInstances.endpoints) chartInstances.endpoints.destroy();

        chartInstances.endpoints = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: data.labels || [],
                datasets: [{
                    data: data.counts || [],
                    backgroundColor: ["#3b82f6", "#10b981", "#8b5cf6", "#f43f5e"],
                    borderWidth: 2,
                    borderColor: "#ffffff"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "right" } }
            }
        });
    }

    // Render Recent Security Events Table using Safe DOM APIs (No innerHTML)
    function renderRecentEvents(data) {
        if (!tbody) return;
        clearElement(tbody);

        const events = data.events || [];
        if (!events.length) {
            if (emptyMsg) emptyMsg.style.display = "block";
            return;
        }

        if (emptyMsg) emptyMsg.style.display = "none";

        events.forEach(ev => {
            const tr = document.createElement("tr");

            // Timestamp
            const tdTime = document.createElement("td");
            tdTime.textContent = ev.created_at ? ev.created_at.replace("T", " ").substring(0, 19) : "";
            tr.appendChild(tdTime);

            // Endpoint
            const tdEndpoint = document.createElement("td");
            const codeEndpoint = document.createElement("code");
            codeEndpoint.textContent = ev.endpoint || "";
            tdEndpoint.appendChild(codeEndpoint);
            tr.appendChild(tdEndpoint);

            // Method
            const tdMethod = document.createElement("td");
            tdMethod.textContent = ev.method || "";
            tr.appendChild(tdMethod);

            // Field
            const tdField = document.createElement("td");
            tdField.textContent = ev.field || "N/A";
            tr.appendChild(tdField);

            // Risk Level Badge
            const tdRisk = document.createElement("td");
            const badgeRisk = document.createElement("span");
            badgeRisk.className = `badge-risk ${ev.risk_level}`;
            badgeRisk.textContent = ev.risk_level || "";
            tdRisk.appendChild(badgeRisk);
            tr.appendChild(tdRisk);

            // Action Badge
            const tdAction = document.createElement("td");
            const badgeAction = document.createElement("span");
            badgeAction.className = `badge-action ${ev.action}`;
            badgeAction.textContent = ev.action || "";
            tdAction.appendChild(badgeAction);
            tr.appendChild(tdAction);

            // Rule ID
            const tdRule = document.createElement("td");
            tdRule.textContent = ev.rule_id || "N/A";
            tr.appendChild(tdRule);

            // Reasoning
            const tdReason = document.createElement("td");
            tdReason.textContent = ev.reason || "Detection rule triggered.";
            tr.appendChild(tdReason);

            tbody.appendChild(tr);
        });
    }

    // Initial Load
    fetchDashboardData();
});
