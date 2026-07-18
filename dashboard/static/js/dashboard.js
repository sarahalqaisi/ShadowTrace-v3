(() => {
  const text = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  const escapeHtml = value => String(value ?? "").replace(/[&<>'"]/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  }[char]));
  const palette = ["#ff5d73", "#ff9657", "#f5c451", "#2bd6a4", "#64748b", "#4b9cff", "#a98bff"];
  const chartText = "#8ea4bc";
  const grid = "rgba(148,180,214,.08)";
  const charts = {};

  function chart(id, type, labels, values, label, options = {}) {
    if (!window.Chart) return;
    const canvas = document.getElementById(id);
    if (!canvas) return;
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(canvas, {
      type,
      data: {
        labels,
        datasets: [{
          label,
          data: values,
          backgroundColor: type === "line" ? "rgba(75,156,255,.18)" : palette,
          borderColor: type === "line" ? "#4b9cff" : palette,
          borderWidth: 1.5,
          fill: type === "line",
          tension: .32
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: type === "doughnut",
            position: "bottom",
            labels: { color: chartText, boxWidth: 10, padding: 16 }
          }
        },
        scales: type === "doughnut" ? {} : {
          x: { ticks: { color: chartText }, grid: { color: grid } },
          y: { beginAtZero: true, ticks: { color: chartText, precision: 0 }, grid: { color: grid } }
        },
        ...options
      }
    });
  }

  function renderCountries(countries) {
    const body = document.getElementById("country-table-body");
    if (!body) return;
    body.innerHTML = countries.length ? countries.slice(0, 8).map(item => `
      <tr>
        <td><span class="country-code">${escapeHtml(item.country_code || "--")}</span><strong>${escapeHtml(item.country)}</strong></td>
        <td>${Number(item.incidents || 0)}</td>
        <td>${Number(item.critical || 0)}</td>
        <td><span class="score-mini">${Number(item.max_threat_score || 0)}</span></td>
      </tr>`).join("") : '<tr><td colspan="4" class="empty-state">No cached GeoIP results yet.</td></tr>';
  }

  async function loadDashboard() {
    document.querySelectorAll(".chart-panel").forEach(panel => panel.classList.add("panel-loading"));
    try {
      const response = await fetch("/api/dashboard", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`Dashboard request failed: ${response.status}`);
      const data = await response.json();
      text("total-incidents", data.total_incidents);
      text("active-threats", data.active_threats);
      text("total-evidence", data.total_evidence);
      text("monitoring-tools", data.monitoring_tools);
      text("avg-confidence", `${data.average_confidence}%`);
      text("avg-threat", `${data.average_threat_score}`);
      text("ioc-total", data.ioc_statistics?.total ?? 0);
      text("ioc-unique", data.ioc_statistics?.unique ?? 0);
      text("ioc-correlated", data.ioc_statistics?.correlated ?? 0);
      chart("severity-chart", "doughnut", Object.keys(data.severity_distribution), Object.values(data.severity_distribution), "Incidents");
      chart("status-chart", "doughnut", Object.keys(data.status_distribution), Object.values(data.status_distribution), "Incidents");
      chart("tool-chart", "bar", Object.keys(data.tool_distribution), Object.values(data.tool_distribution), "Evidence", { plugins: { legend: { display: false } } });
      chart("trend-chart", "line", data.incident_trend.map(item => item.day), data.incident_trend.map(item => item.total), "Incidents", { plugins: { legend: { display: false } } });
      chart("country-chart", "bar", Object.keys(data.country_distribution || {}), Object.values(data.country_distribution || {}), "Incidents", { indexAxis: "y", plugins: { legend: { display: false } } });
      renderCountries(data.countries || []);
    } catch (error) {
      console.warn("Dashboard refresh failed", error);
    } finally {
      document.querySelectorAll(".chart-panel").forEach(panel => panel.classList.remove("panel-loading"));
    }
  }

  async function loadMap() {
    if (!window.L || !document.getElementById("map")) return;
    const map = L.map("map", { scrollWheelZoom: false }).setView([24, 18], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: "&copy; OpenStreetMap contributors"
    }).addTo(map);
    try {
      const response = await fetch("/api/map", { headers: { Accept: "application/json" } });
      const points = response.ok ? await response.json() : [];
      const bounds = [];
      points.forEach(point => {
        const latlng = [Number(point.latitude), Number(point.longitude)];
        if (!Number.isFinite(latlng[0]) || !Number.isFinite(latlng[1])) return;
        bounds.push(latlng);
        const popup = `<strong>${escapeHtml(point.title)}</strong><br>${escapeHtml(point.ip)}<br>${escapeHtml(point.city || "")}, ${escapeHtml(point.country || "")}<br>Threat score: ${escapeHtml(point.threat_score ?? 0)}/100`;
        L.circleMarker(latlng, { radius: 7, weight: 2, color: "#4b9cff", fillColor: "#ff5d73", fillOpacity: .8 })
          .addTo(map)
          .bindPopup(popup);
      });
      if (bounds.length) map.fitBounds(bounds, { padding: [35, 35], maxZoom: 5 });
      else document.getElementById("map-empty")?.removeAttribute("hidden");
    } catch (error) {
      console.warn("Map data failed", error);
    }
  }

  loadDashboard();
  loadMap();
  window.setInterval(loadDashboard, 60000);
})();
