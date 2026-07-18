(() => {
  const tabs = [...document.querySelectorAll(".tab")];
  const panels = [...document.querySelectorAll(".tab-panel")];
  function activate(name, updateHash = true) {
    if (!panels.some(panel => panel.id === name)) name = "overview";
    tabs.forEach(tab => tab.classList.toggle("active", tab.dataset.tab === name));
    panels.forEach(panel => panel.classList.toggle("active", panel.id === name));
    if (updateHash) history.replaceState(null, "", `#${name}`);
    if (name === "intelligence" && window.incidentMap) setTimeout(() => window.incidentMap.invalidateSize(), 80);
  }
  tabs.forEach(tab => tab.addEventListener("click", () => activate(tab.dataset.tab)));
  activate(location.hash.replace("#", "") || "overview", false);
  window.addEventListener("hashchange", () => activate(location.hash.replace("#", ""), false));

  const mapNode = document.getElementById("incident-map");
  if (mapNode && window.L) {
    const lat = Number(mapNode.dataset.lat);
    const lon = Number(mapNode.dataset.lon);
    if (Number.isFinite(lat) && Number.isFinite(lon)) {
      window.incidentMap = L.map(mapNode, { scrollWheelZoom: false }).setView([lat, lon], 7);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "&copy; OpenStreetMap contributors" }).addTo(window.incidentMap);
      L.marker([lat, lon]).addTo(window.incidentMap).bindPopup(mapNode.dataset.label || "Source IP").openPopup();
    }
  }
})();
