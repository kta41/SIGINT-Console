#!/usr/bin/env python3
"""
dashboard_html.py — Generador de Consola SIGINT / Auditoría Corporativa (HTML autocontenido).

Genera una Single-Page Application (SPA) interactiva 100 % offline con:
- Pestañas: Resumen Ejecutivo, Inteligencia de Redes (APs/SSIDs), Inteligencia de
  Dispositivos (STAs + PNL Probe Requests), Persistencia Multi-Sesión, Sesiones & GPS
  y Gestor de Etiquetas (tags.json).
- Dossiers interactivos clicables para cada Red (BSSID/SSID), Dispositivo (STA) y Sesión.
- Etiquetado en vivo (nombres custom + categoría) para Sesiones, Redes y Dispositivos,
   más asignación de coordenadas GPS por sesión, persistido en localStorage y exportable
  / importable como `tags.json`.
"""

import json
from pathlib import Path


def render_sigint_dashboard(dataset: dict, initial_tags: dict, html_path: Path) -> None:
    dataset_json = json.dumps(dataset, ensure_ascii=False, separators=(",", ":"))
    tags_json = json.dumps(initial_tags, ensure_ascii=False, separators=(",", ":"))

    doc = rf"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIGINT Wireless Intelligence Console — Wardrive ESP32-S3</title>
<style>
:root {{
  --bg: #070b14;
  --bg-panel: #0f172a;
  --bg-card: #131c31;
  --bg-hover: #1e293b;
  --border: #1e293b;
  --border-hi: #334155;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --accent-dim: rgba(56,189,248,0.14);
  --green: #10b981;
  --amber: #f59e0b;
  --red: #ef4444;
  --purple: #a855f7;
  --font-mono: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 13.5px;
  line-height: 1.45;
}}
header {{
  background: linear-gradient(180deg, #0f172a 0%, #090e1a 100%);
  border-bottom: 1px solid var(--border-hi);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  position: sticky;
  top: 0;
  z-index: 50;
}}
.brand {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.brand-badge {{
  background: var(--accent-dim);
  border: 1px solid var(--accent);
  color: var(--accent);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 4px;
  letter-spacing: 0.08em;
}}
.brand h1 {{
  margin: 0;
  font-size: 17px;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: #f8fafc;
}}
.brand-sub {{
  color: var(--muted);
  font-size: 12px;
  font-family: var(--font-mono);
}}
.top-actions {{
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}}
button, .btn {{
  background: var(--bg-card);
  color: var(--text);
  border: 1px solid var(--border-hi);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12.5px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}}
button:hover, .btn:hover {{
  border-color: var(--accent);
  background: var(--bg-hover);
}}
.btn-primary {{
  background: #0284c7;
  border-color: #38bdf8;
  color: #fff;
}}
.btn-primary:hover {{
  background: #0369a1;
}}
nav.tabs {{
  display: flex;
  gap: 4px;
  padding: 0 24px;
  background: #090e1a;
  border-bottom: 1px solid var(--border-hi);
  overflow-x: auto;
}}
.tab-btn {{
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  padding: 11px 16px;
  color: var(--muted);
  font-weight: 600;
  font-size: 13px;
}}
.tab-btn:hover {{
  color: #fff;
  background: rgba(255,255,255,0.02);
}}
.tab-btn.active {{
  color: var(--accent);
  border-bottom-color: var(--accent);
  background: rgba(56,189,248,0.06);
}}
main {{
  padding: 20px 24px 60px;
  max-width: 1680px;
  margin: 0 auto;
}}
.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}}
.kpi {{
  background: var(--bg-panel);
  border: 1px solid var(--border-hi);
  border-radius: 8px;
  padding: 14px 16px;
}}
.kpi-label {{
  color: var(--muted);
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 6px;
}}
.kpi-val {{
  font-size: 24px;
  font-weight: 700;
  font-family: var(--font-mono);
  color: #f8fafc;
}}
.kpi-sub {{
  color: var(--muted);
  font-size: 11.5px;
  margin-top: 4px;
}}
.grid-2 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}}
.panel {{
  background: var(--bg-panel);
  border: 1px solid var(--border-hi);
  border-radius: 8px;
  padding: 16px 18px;
  margin-bottom: 18px;
}}
.panel-title {{
  margin: 0 0 12px 0;
  font-size: 14px;
  font-weight: 700;
  color: #f8fafc;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}}
.toolbar {{
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 12px;
}}
input[type="text"], input[type="number"], select, textarea {{
  background: #080d19;
  color: var(--text);
  border: 1px solid var(--border-hi);
  border-radius: 6px;
  padding: 7px 11px;
  font-size: 13px;
}}
input[type="text"]:focus, select:focus, textarea:focus {{
  outline: none;
  border-color: var(--accent);
}}
.chip-group {{
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}}
.chip {{
  font-size: 11.5px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--border-hi);
  background: var(--bg-card);
  color: var(--muted);
  cursor: pointer;
}}
.chip.active {{
  background: var(--accent-dim);
  border-color: var(--accent);
  color: var(--accent);
  font-weight: 600;
}}
.table-wrap {{
  overflow-x: auto;
  max-height: 68vh;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 6px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 12.8px;
}}
th, td {{
  padding: 9px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: middle;
}}
th {{
  background: #0b1120;
  color: var(--muted);
  font-weight: 600;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  cursor: pointer;
  user-select: none;
  position: sticky;
  top: 0;
  z-index: 10;
  box-shadow: 0 1px 0 var(--border-hi);
}}
tr:hover td {{
  background: rgba(56,189,248,0.04);
}}
code, .mono {{
  font-family: var(--font-mono);
  font-size: 12px;
}}
.entity-link {{
  color: var(--accent);
  cursor: pointer;
  text-decoration: none;
  font-weight: 600;
}}
.entity-link:hover {{
  text-decoration: underline;
}}
.badge {{
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  font-family: var(--font-mono);
  border: 1px solid transparent;
}}
.b-own {{ background: rgba(16,185,129,0.16); color: #34d399; border-color: rgba(16,185,129,0.4); }}
.b-known {{ background: rgba(56,189,248,0.16); color: #38bdf8; border-color: rgba(56,189,248,0.4); }}
.b-target {{ background: rgba(245,158,11,0.18); color: #fbbf24; border-color: rgba(245,158,11,0.45); }}
.b-suspicious {{ background: rgba(239,68,68,0.18); color: #f87171; border-color: rgba(239,68,68,0.45); }}
.b-multi {{ background: rgba(168,85,247,0.18); color: #c084fc; border-color: rgba(168,85,247,0.45); }}
.b-neutral {{ background: #1e293b; color: #cbd5e1; border-color: #334155; }}
.rssi-bar {{
  display: inline-block;
  width: 54px;
  height: 6px;
  background: #1e293b;
  border-radius: 3px;
  overflow: hidden;
  vertical-align: middle;
  margin-right: 6px;
}}
.rssi-fill {{ height: 100%; }}
.bar-row {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
  font-size: 12px;
}}
.bar-label {{ width: 90px; color: var(--muted); font-family: var(--font-mono); }}
.bar-track {{ flex: 1; height: 10px; background: #090e1a; border-radius: 4px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: linear-gradient(90deg, #0284c7, #38bdf8); }}
.bar-count {{ width: 48px; text-align: right; font-family: var(--font-mono); }}
/* Modal Dossier / Editor de Tags */
.modal-backdrop {{
  position: fixed;
  inset: 0;
  background: rgba(3,7,18,0.78);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 200;
  padding: 20px;
}}
.modal-backdrop.open {{ display: flex; }}
.modal {{
  background: var(--bg-panel);
  border: 1px solid var(--border-hi);
  border-radius: 10px;
  max-width: 880px;
  width: 100%;
  max-height: 88vh;
  overflow-y: auto;
  padding: 20px 24px;
  box-shadow: 0 24px 48px rgba(0,0,0,0.6);
}}
.modal-header {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  border-bottom: 1px solid var(--border-hi);
  padding-bottom: 12px;
  margin-bottom: 16px;
}}
.kv-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}}
.kv {{
  background: var(--bg-card);
  padding: 10px 12px;
  border-radius: 6px;
  border: 1px solid var(--border);
}}
.kv-k {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
.kv-v {{ font-family: var(--font-mono); font-size: 13px; font-weight: 600; margin-top: 2px; }}
@media print {{
  header, nav.tabs, .toolbar, .no-print {{ display: none !important; }}
  .tab-pane {{ display: block !important; page-break-after: always; }}
  body {{ background: #fff; color: #000; }}
  .panel, .kpi {{ border: 1px solid #ccc; background: #fff; }}
}}
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="brand-badge">SIGINT // 802.11</span>
    <div>
      <h1>Wireless Intelligence &amp; Correlation Console</h1>
      <div class="brand-sub" id="hdr-summary">Cargando telemetría...</div>
    </div>
  </div>
  <div class="top-actions no-print">
    <label class="btn btn-primary" id="srv-upload-btn" style="display:none">📥 Importar .JSONL / .PCAP <input type="file" accept=".jsonl,.json,.ndjson,.pcap" multiple style="display:none" onchange="uploadJsonlFiles(event)"></label>
    <a class="btn" id="hc22000-dl-btn" href="/export/hc22000" style="display:none;border-color:rgba(245,158,11,0.55);color:#fbbf24">🔓 Descargar .hc22000</a>
    <button onclick="openTagManagerModal()">🏷️ Nuevo Tag / Alias</button>
    <button onclick="exportTagsJson()">💾 Exportar tags.json</button>
    <label class="btn">📂 Importar tags.json <input type="file" accept=".json" style="display:none" onchange="importTagsJson(event)"></label>
    <button onclick="window.print()">🖨️ Informe PDF</button>
  </div>
</header>

<nav class="tabs no-print">
  <button class="tab-btn active" onclick="switchTab('overview', this)">1. Resumen Ejecutivo &amp; Riesgos</button>
  <button class="tab-btn" onclick="switchTab('networks', this)">2. Inteligencia de Redes (APs / SSIDs)</button>
  <button class="tab-btn" onclick="switchTab('devices', this)">3. Inteligencia de Dispositivos (STAs &amp; PNL)</button>
  <button class="tab-btn" onclick="switchTab('cross', this)">4. Álgebra de Conjuntos &amp; Cruce Multi-Sesión</button>
  <button class="tab-btn" onclick="switchTab('sessions', this)">5. Sesiones, PCAP &amp; GPS</button>
  <button class="tab-btn" onclick="switchTab('tags', this)">6. Registro de Identidades (Tags)</button>
</nav>

<main>
  <!-- TAB 1: OVERVIEW -->
  <section id="tab-overview" class="tab-pane active">
    <div class="kpi-grid" id="kpi-container"></div>
    <div class="grid-2">
      <div class="panel">
        <h3 class="panel-title">Ocupación del Espectro 2,4 GHz (Canales 1–14)</h3>
        <div id="chart-channels"></div>
      </div>
      <div class="panel">
        <h3 class="panel-title">Postura Criptográfica &amp; Superficie de Exposición</h3>
        <div id="chart-security"></div>
      </div>
    </div>
    <div class="panel">
      <h3 class="panel-title">Hallazgos de Auditoría &amp; Correlación Automática (Audit Findings)</h3>
      <div id="findings-list"></div>
    </div>
  </section>

  <!-- TAB 2: NETWORKS -->
  <section id="tab-networks" class="tab-pane">
    <div class="panel">
      <h3 class="panel-title">
        <span>Catálogo de Redes e Infraestructura (BSSIDs / Clusters SSID)</span>
        <span class="mono" id="net-count-label"></span>
      </h3>
      <div class="toolbar">
        <input type="text" id="net-search" placeholder="Consulta DSL o texto (ej: rssi>-65 and not tag:PROPIO and pcap:EAPOL)" style="min-width:390px;flex:1" oninput="renderNetworksTable()">
        <select id="net-session-filter" onchange="renderNetworksTable()">
          <option value="">Todas las sesiones</option>
        </select>
        <select id="net-not-session-filter" onchange="renderNetworksTable()" title="Excluir redes vistas en esta sesión (Diferencia rápida)">
          <option value="">Excluir sesión: Ninguna</option>
        </select>
        <button class="no-print" onclick="bulkTagCurrentNetworks()">🏷️ Etiquetar Filtradas</button>
      </div>
      <div class="toolbar" style="margin-top:-4px">
        <div class="chip-group" id="net-chips">
          <span class="chip active" onclick="setNetFilter('all', this)">Todas</span>
          <span class="chip" onclick="setNetFilter('insecure', this)" style="border-color:rgba(239,68,68,0.45);color:#f87171">⚠️ Redes No Seguras (OPEN/WEP/TKIP/WPS)</span>
          <span class="chip" onclick="setNetFilter('weak', this)">Cifrado Débil (OPEN/WEP/TKIP)</span>
          <span class="chip" onclick="setNetFilter('wps', this)">WPS Expuesto</span>
          <span class="chip" onclick="setNetFilter('pcap', this)" style="border-color:rgba(16,185,129,0.45);color:#34d399">📦 Con Trazas PCAP</span>
          <span class="chip" onclick="setNetFilter('eapol', this)" style="border-color:rgba(245,158,11,0.55);color:#fbbf24">🔑 EAPOL / Handshake</span>
          <span class="chip" onclick="setNetFilter('multi', this)">Multi-Sesión (&ge;2)</span>
          <span class="chip" onclick="setNetFilter('clients', this)">Con Clientes Activos</span>
          <span class="chip" onclick="setNetFilter('probed', this)">Buscadas por STAs</span>
          <span class="chip" onclick="setNetFilter('hidden', this)">SSID Oculto</span>
          <span class="chip" onclick="setNetFilter('tagged', this)">Etiquetadas</span>
          <span class="chip" onclick="setNetFilter('untagged', this)">Sin Etiqueta</span>
        </div>
      </div>
      <div id="net-vuln-banner" style="display:none;margin-bottom:14px"></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>RSSI Máx</th>
              <th>CH</th>
              <th>SSID / Cluster</th>
              <th>BSSID</th>
              <th>Tag / Alias</th>
              <th>Seguridad</th>
              <th>WPS</th>
              <th>Trazas PCAP</th>
              <th>Clientes (STAs)</th>
              <th>Buscada por</th>
              <th>Sesiones</th>
              <th>Fabricante OUI</th>
              <th class="no-print">Acción</th>
            </tr>
          </thead>
          <tbody id="net-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 3: DEVICES (STAs & PNL) -->
  <section id="tab-devices" class="tab-pane">
    <div class="panel">
      <h3 class="panel-title">
        <span>Inteligencia de Dispositivos Clientes (Asociaciones + Huella PNL de Redes Buscadas)</span>
        <span class="mono" id="dev-count-label"></span>
      </h3>
      <div class="toolbar">
        <input type="text" id="dev-search" placeholder="Consulta DSL o texto (ej: session:A and not session:B and rssi>-70 and not mac:random)" style="min-width:410px;flex:1" oninput="renderDevicesTable()">
        <select id="dev-session-filter" onchange="renderDevicesTable()">
          <option value="">En sesión: Todas</option>
        </select>
        <select id="dev-not-session-filter" onchange="renderDevicesTable()" title="Excluir dispositivos vistos en esta sesión (ej. en A pero NO en B)">
          <option value="">Excluir sesión: Ninguna</option>
        </select>
        <button class="no-print" onclick="bulkTagCurrentDevices()">🏷️ Etiquetar Filtrados</button>
      </div>
      <div class="toolbar" style="margin-top:-4px">
        <div class="chip-group" id="dev-chips">
          <span class="chip active" onclick="setDevFilter('all', this)">Todos</span>
          <span class="chip" onclick="setDevFilter('insecure_ap', this)" style="border-color:rgba(239,68,68,0.45);color:#f87171">⚠️ En Red No Segura</span>
          <span class="chip" onclick="setDevFilter('pcap', this)" style="border-color:rgba(16,185,129,0.45);color:#34d399">📦 Con Trazas PCAP</span>
          <span class="chip" onclick="setDevFilter('eapol', this)" style="border-color:rgba(245,158,11,0.55);color:#fbbf24">🔑 EAPOL / Handshake</span>
          <span class="chip" onclick="setDevFilter('multi', this)">Recurrentes (&ge;2 sesiones)</span>
          <span class="chip" onclick="setDevFilter('associated', this)">Asociados a un AP</span>
          <span class="chip" onclick="setDevFilter('probing', this)">Buscando Redes (PNL)</span>
          <span class="chip" onclick="setDevFilter('matched', this)">Busca Red Presente Aquí</span>
          <span class="chip" onclick="setDevFilter('global_mac', this)">MAC Real IEEE (No aleatoria)</span>
          <span class="chip" onclick="setDevFilter('tagged', this)">Etiquetados</span>
          <span class="chip" onclick="setDevFilter('untagged', this)">Sin Etiqueta</span>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>RSSI</th>
              <th>Dispositivo (STA MAC)</th>
              <th>Tag / Alias</th>
              <th>Tipo MAC / Fabricante</th>
              <th>Asociado a AP (BSSID / SSID)</th>
              <th>Redes que Busca (Probe Requests PNL)</th>
              <th>Trazas PCAP</th>
              <th>Tramas</th>
              <th>Sesiones Visto</th>
              <th class="no-print">Acción</th>
            </tr>
          </thead>
          <tbody id="dev-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 4: CROSS-SESSION PERSISTENCE -->
  <section id="tab-cross" class="tab-pane">
    <div class="panel">
      <h3 class="panel-title">Correlación Multi-Sesión — Dispositivos y Redes Recurrentes</h3>
      <p style="color:var(--muted);margin-top:0">
        Identifica qué dispositivos (<code>STA MAC</code>) o puntos de acceso (<code>BSSID</code>) han aparecido en múltiples sesiones distintas, o qué dispositivos con MAC rotada comparten la misma huella de redes buscadas (PNL).
      </p>
      <div id="cross-content"></div>
    </div>
  </section>

  <!-- TAB 5: SESSIONS & GPS -->
  <section id="tab-sessions" class="tab-pane">
    <div class="panel">
      <h3 class="panel-title">Gestión de Sesiones de Captura &amp; Geolocalización (GPS Vinculado a la Sesión)</h3>
      <p style="color:var(--muted);margin-top:0">
        El GPS se asocia a nivel de <b>Sesión</b>. Desde aquí puedes nombrar cada sesión (ej. <i>"Auditoría Planta 2"</i>, <i>"Paseo Centro"</i>) y asignarle o corregir sus coordenadas GPS.
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Session ID</th>
              <th>Nombre de Sesión (Tag)</th>
              <th>Fichero Origen</th>
              <th>Inicio → Fin</th>
              <th>Escaneos</th>
              <th>APs Únicos</th>
              <th>Clientes (STAs)</th>
              <th>Archivo PCAP</th>
              <th>GPS de la Sesión (Lat, Lon)</th>
              <th class="no-print">Editar</th>
            </tr>
          </thead>
          <tbody id="sessions-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 6: TAGS REGISTRY -->
  <section id="tab-tags" class="tab-pane">
    <div class="panel">
      <h3 class="panel-title">
        <span>Registro Maestro de Identidades, Nombres Custom y Etiquetas (<code>tags.json</code>)</span>
        <button class="btn-primary" onclick="exportTagsJson()">💾 Descargar tags.json</button>
      </h3>
      <p style="color:var(--muted);margin-top:0">
        Guarda el archivo descargado como <code>wardrive_data/tags.json</code> para que <code>warmap</code> y <code>warpull</code> lo incrusten automáticamente en futuros informes y CSVs.
      </p>
      <div id="tags-registry-content"></div>
    </div>
  </section>
</main>

<!-- MODAL DOSSIER / TAG EDITOR -->
<div class="modal-backdrop" id="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modal-body"></div>
</div>

<script>
const DATA = {dataset_json};
const INITIAL_TAGS = {tags_json};
const STORAGE_KEY = "wardrive_sigint_tags_v1";

let TAGS = loadTags();
let netFilter = "all";
let devFilter = "all";
let lastFilteredNetworks = [];
let lastFilteredDevices = [];
let setAlgState = {{
  entity: "devices",
  op: "diff_ab",
  groupA: [],
  groupB: [],
  groupC: [],
  initialized: false,
}};

/* ---------------- EVALUADOR DE CONSULTAS AVANZADAS (DSL) ---------------- */

function evalSingleAtom(atomRaw, item, entityType) {{
  let atom = atomRaw.trim();
  if (!atom) return true;
  let neg = false;
  if (/^(not\\s+|!|-)/i.test(atom)) {{
    neg = true;
    atom = atom.replace(/^(not\\s+|!|-)/i, "").trim();
  }}
  const res = evalPositiveAtom(atom, item, entityType);
  return neg ? !res : res;
}}

function matchSessionToken(sessionsArr, val) {{
  const v = val.toLowerCase();
  return (sessionsArr || []).some(sid => {{
    const disp = getSessionDisplay(sid).toLowerCase();
    return sid.toLowerCase().includes(v) || disp.includes(v);
  }});
}}

function evalPositiveAtom(atom, item, entityType) {{
  const mNum = atom.match(/^(rssi|ch|channel|clients|stas|sessions|frames|sightings)\\s*(>=|<=|!=|=|>|<|:)\\s*(-?\\d+)$/i);
  if (mNum) {{
    const field = mNum[1].toLowerCase();
    const op = mNum[2] === ":" ? "=" : mNum[2];
    const target = parseInt(mNum[3], 10);
    let actual = 0;
    if (field === "rssi") actual = item.rssi;
    else if (field === "ch" || field === "channel") actual = entityType === "ap" ? item.primary_channel : item.channel;
    else if (field === "clients" || field === "stas") actual = (item.clients || []).length;
    else if (field === "sessions") actual = (item.sessions || []).length;
    else if (field === "frames") actual = item.total_frames || item.pcap_frames || 0;
    else if (field === "sightings") actual = item.sightings || 0;

    if (op === ">") return actual > target;
    if (op === ">=") return actual >= target;
    if (op === "<") return actual < target;
    if (op === "<=") return actual <= target;
    if (op === "!=") return actual !== target;
    return actual === target;
  }}

  const mKv = atom.match(/^([a-z_]+)\\s*(:|=|!=)\\s*(.+)$/i);
  if (mKv) {{
    const k = mKv[1].toLowerCase();
    const isNeq = mKv[2] === "!=";
    const v = mKv[3].replace(/^["']|["']$/g, "").toLowerCase().trim();
    const tag = entityType === "ap" ? getNetworkTag(item.bssid, item.ssid) : getDeviceTag(item.sta_mac);
    const traces = (item.pcap_traces || []).map(x => x.toLowerCase());
    let hit = false;

    if (k === "session" || k === "ses") {{
      hit = matchSessionToken(item.sessions, v);
    }} else if (k === "pcap" || k === "trace") {{
      hit = v === "any" || v === "true" ? traces.length > 0 : traces.some(t => t.includes(v));
    }} else if (k === "tag" || k === "cat" || k === "category") {{
      if (v === "none" || v === "false" || v === "empty") {{
        hit = !tag || !tag.label;
      }} else if (v === "any" || v === "true") {{
        hit = Boolean(tag && tag.label);
      }} else {{
        const tStr = ((tag ? tag.label : "") + " " + (tag ? tag.category : "")).toLowerCase();
        hit = tStr.includes(v);
      }}
    }} else if (k === "vendor" || k === "oui") {{
      const wpsMan = item.wps_info && item.wps_info.manufacturer ? item.wps_info.manufacturer : "";
      hit = ((item.vendor || "") + " " + wpsMan).toLowerCase().includes(v);
    }} else if (k === "ssid") {{
      if (entityType === "ap") hit = (item.ssid || "").toLowerCase().includes(v);
      else hit = [...(item.associated_ssids || []), ...(item.probed_ssids || [])].some(s => s.toLowerCase().includes(v));
    }} else if (k === "probe" || k === "pnl") {{
      const arr = entityType === "ap" ? (item.probing_stas || []) : (item.probed_ssids || []);
      hit = v === "any" || v === "true" ? arr.length > 0 : arr.some(s => s.toLowerCase().includes(v));
    }} else if (k === "bssid" || k === "ap") {{
      if (entityType === "ap") hit = (item.bssid || "").toLowerCase().includes(v);
      else hit = (item.associated_bssids || []).some(b => b.toLowerCase().includes(v));
    }} else if (k === "mac" || k === "sta") {{
      if (v === "random" || v === "laa") hit = Boolean(item.is_randomized);
      else if (v === "global" || v === "real" || v === "ieee") hit = !item.is_randomized;
      else hit = ((item.sta_mac || item.bssid || "")).toLowerCase().includes(v);
    }} else if (k === "auth" || k === "sec") {{
      hit = ((item.auth_mode || "") + " " + (item.pairwise_cipher || "")).toLowerCase().includes(v);
    }} else if (k === "wps") {{
      if (v === "true" || v === "yes" || v === "si" || v === "1") hit = Boolean(item.wps);
      else if (v === "false" || v === "no" || v === "0") hit = !item.wps;
      else hit = JSON.stringify(item.wps_info || {{}}).toLowerCase().includes(v);
    }} else if (k === "hidden") {{
      hit = (v === "true" || v === "1" || v === "si") ? Boolean(item.hidden) : !item.hidden;
    }} else if (k === "fp" || k === "ie") {{
      hit = (item.ie_fingerprint || "").toLowerCase().includes(v);
    }} else {{
      hit = buildHaystack(item, entityType).includes(atom.toLowerCase());
    }}
    return isNeq ? !hit : hit;
  }}

  return buildHaystack(item, entityType).includes(atom.toLowerCase());
}}

function buildHaystack(item, entityType) {{
  const tag = entityType === "ap" ? getNetworkTag(item.bssid, item.ssid) : getDeviceTag(item.sta_mac);
  const wpsStr = item.wps_info ? Object.values(item.wps_info).join(" ") : "";
  if (entityType === "ap") {{
    return [
      item.ssid, item.bssid, item.vendor, item.auth_mode, item.pairwise_cipher,
      "ch" + item.primary_channel, tag ? tag.label : "", tag ? tag.category : "",
      wpsStr, ...(item.pcap_traces || []), ...(item.deauth_reasons || [])
    ].join(" ").toLowerCase();
  }}
  return [
    item.sta_mac, item.vendor, item.ie_fingerprint || "",
    ...(item.probed_ssids || []), ...(item.associated_bssids || []),
    ...(item.associated_ssids || []), ...(item.pcap_traces || []),
    tag ? tag.label : "", tag ? tag.category : ""
  ].join(" ").toLowerCase();
}}

function evaluateDslQuery(queryStr, item, entityType) {{
  const q = (queryStr || "").trim();
  if (!q) return true;
  // Separar por OR (|) y dentro de cada rama por AND (& o espacio con palabras clave)
  const orBranches = q.split(/\\s+or\\s+|\\s*\\|\\|\\s*/i);
  return orBranches.some(branch => {{
    const andAtoms = branch.split(/\\s+and\\s+|\\s*&&\\s*/i);
    return andAtoms.every(atom => evalSingleAtom(atom, item, entityType));
  }});
}}

function loadTags() {{
  const base = {{
    sessions: Object.assign({{}}, INITIAL_TAGS.sessions || {{}}),
    networks: Object.assign({{}}, INITIAL_TAGS.networks || {{}}),
    devices: Object.assign({{}}, INITIAL_TAGS.devices || {{}})
  }};
  try {{
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {{
      const saved = JSON.parse(raw);
      Object.assign(base.sessions, saved.sessions || {{}});
      Object.assign(base.networks, saved.networks || {{}});
      Object.assign(base.devices, saved.devices || {{}});
    }}
  }} catch (e) {{}}
  return base;
}}

function saveTags() {{
  try {{
    localStorage.setItem(STORAGE_KEY, JSON.stringify(TAGS));
  }} catch (e) {{}}
  if (window.location.protocol.startsWith("http")) {{
    fetch("/api/tags", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(TAGS)
    }}).catch(() => {{}});
  }}
  renderAll();
}}

async function uploadJsonlFiles(ev) {{
  const files = Array.from(ev.target.files || []);
  if (!files.length) return;
  for (const f of files) {{
    if (f.name.toLowerCase().endsWith(".pcap")) {{
      const buf = await f.arrayBuffer();
      await fetch("/api/import_pcap?filename=" + encodeURIComponent(f.name), {{
        method: "POST",
        headers: {{ "Content-Type": "application/octet-stream" }},
        body: buf
      }});
    }} else {{
      const text = await f.text();
      await fetch("/api/import?filename=" + encodeURIComponent(f.name), {{
        method: "POST",
        headers: {{ "Content-Type": "application/x-ndjson" }},
        body: text
      }});
    }}
  }}
  window.location.reload();
}}

function esc(s) {{
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}}

function catBadgeClass(cat) {{
  switch ((cat || "").toUpperCase()) {{
    case "PROPIO": return "b-own";
    case "CONOCIDO": return "b-known";
    case "OBJETIVO": return "b-target";
    case "SOSPECHOSO": return "b-suspicious";
    default: return "b-neutral";
  }}
}}

function getSessionTag(sid) {{
  return TAGS.sessions[sid] || {{}};
}}

function getSessionDisplay(sid) {{
  const t = getSessionTag(sid);
  return t.name ? `${{t.name}} (${{sid}})` : sid;
}}

function getNetworkTag(bssid, ssid) {{
  if (bssid && TAGS.networks[bssid.toUpperCase()]) return TAGS.networks[bssid.toUpperCase()];
  if (ssid && TAGS.networks["SSID:" + ssid]) return TAGS.networks["SSID:" + ssid];
  return null;
}}

function getDeviceTag(mac) {{
  if (!mac) return null;
  return TAGS.devices[mac.toUpperCase()] || null;
}}

function renderTagBadge(tagObj) {{
  if (!tagObj || !tagObj.label) return '<span style="color:var(--muted)">—</span>';
  const cls = catBadgeClass(tagObj.category);
  const cat = tagObj.category ? `[${{esc(tagObj.category)}}] ` : "";
  return `<span class="badge ${{cls}}">${{cat}}${{esc(tagObj.label)}}</span>`;
}}

function renderPcapTracesBadges(traces, framesCount) {{
  const arr = Array.isArray(traces) ? traces : [];
  if (arr.length === 0) return '<span style="color:var(--muted)">—</span>';
  const badgeMap = {{
    HANDSHAKE:  {{ cls: "b-suspicious", label: "🔓 HANDSHAKE",  tip: "4-Way Handshake WPA completo (M1+M2) extraíble a hc22000" }},
    PMKID:      {{ cls: "b-target",     label: "🗝️ PMKID",      tip: "RSN PMKID en EAPOL M1 capturado y extraíble a hc22000" }},
    EAPOL:      {{ cls: "b-target",     label: "🔑 EAPOL",      tip: "Trama EAPOL (0x888E) de negociación WPA capturada en PCAP" }},
    DEAUTH:     {{ cls: "b-suspicious", label: "⚡ DEAUTH",     tip: "Trama Deauthentication / Disassociation capturada en PCAP" }},
    ASSOC:      {{ cls: "b-own",        label: "🔗 ASSOC",      tip: "Association / Reassociation Req/Resp capturada en PCAP" }},
    AUTH:       {{ cls: "b-own",        label: "🛡️ AUTH",       tip: "Trama Authentication 802.11 capturada en PCAP" }},
    PROBE_REQ:  {{ cls: "b-known",      label: "📡 PROBE_REQ",  tip: "Probe Request de cliente capturada en PCAP" }},
    PROBE_RESP: {{ cls: "b-known",      label: "📶 PROBE_RESP", tip: "Probe Response de AP capturada en PCAP" }},
    ACTION:     {{ cls: "b-multi",      label: "⚙️ ACTION",     tip: "Trama 802.11 Action (802.11k/v/w, BlockAck) capturada en PCAP" }},
    BEACON:     {{ cls: "b-neutral",    label: "📻 BEACON",     tip: "Baliza 802.11 Beacon con IEs RSN/WPS completos en PCAP" }},
    DATA:       {{ cls: "b-neutral",    label: "📦 DATA",       tip: "Trama de datos 802.11 capturada en PCAP" }},
  }};
  const html = arr.map(t => {{
    const m = badgeMap[t] || {{ cls: "b-neutral", label: t, tip: "Traza PCAP: " + t }};
    return `<span class="badge ${{m.cls}}" title="${{esc(m.tip)}}" style="margin:1px 2px 1px 0">${{m.label}}</span>`;
  }}).join("");
  const cnt = framesCount ? ` <span class="mono" style="color:var(--muted);font-size:11px">(${{framesCount}} pkts)</span>` : "";
  return `<div style="display:flex;flex-wrap:wrap;align-items:center;gap:2px">${{html}}${{cnt}}</div>`;
}}

function rssiBar(rssi) {{
  const pct = Math.max(5, Math.min(100, Math.round(((rssi + 100) / 70) * 100)));
  const color = rssi >= -55 ? "#10b981" : (rssi >= -75 ? "#f59e0b" : "#64748b");
  return `<span class="rssi-bar"><span class="rssi-fill" style="width:${{pct}}%;background:${{color}}"></span></span><span class="mono">${{rssi}} dBm</span>`;
}}

function switchTab(id, btn) {{
  document.querySelectorAll(".tab-pane").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
  document.getElementById("tab-" + id).classList.add("active");
  if (btn) btn.classList.add("active");
}}

function renderOverview() {{
  const sCount = DATA.sessions.length;
  const apCount = DATA.aps.length;
  const devCount = DATA.devices.length;
  const multiDevs = DATA.devices.filter(d => d.sessions.length >= 2).length;
  const multiAps = DATA.aps.filter(a => a.sessions.length >= 2).length;
  const weakAps = DATA.aps.filter(a => a.is_weak).length;
  const wpsAps = DATA.aps.filter(a => a.wps).length;

  // Calcular postura de riesgo (0-100)
  const riskScore = Math.min(100, Math.round(
    (weakAps * 6) + (wpsAps * 1.5) + (DATA.totals.deauth_frames * 5) + (DATA.ssid_collisions.length * 4)
  ));
  const riskColor = riskScore >= 60 ? "var(--red)" : (riskScore >= 30 ? "var(--amber)" : "var(--green)");

  document.getElementById("hdr-summary").textContent =
    `${{sCount}} sesiones | ${{DATA.total_scans}} barridos | ${{apCount}} BSSIDs | ${{devCount}} dispositivos (STAs) | Generado: ${{DATA.generated_at}}`;

  document.getElementById("kpi-container").innerHTML = `
    <div class="kpi">
      <div class="kpi-label">Índice de Exposición RF</div>
      <div class="kpi-val" style="color:${{riskColor}}">${{riskScore}} / 100</div>
      <div class="kpi-sub">${{weakAps}} redes débiles · ${{wpsAps}} con WPS</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Infraestructura (BSSIDs)</div>
      <div class="kpi-val">${{apCount}}</div>
      <div class="kpi-sub">${{DATA.unique_ssids}} SSIDs únicos · ${{multiAps}} en &ge;2 sesiones</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Dispositivos (STAs)</div>
      <div class="kpi-val">${{devCount}}</div>
      <div class="kpi-sub">${{multiDevs}} vistos en múltiples sesiones</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Redes Buscadas (PNL)</div>
      <div class="kpi-val">${{DATA.probed_ssids_count}}</div>
      <div class="kpi-sub">${{DATA.matched_probes_count}} coinciden con APs presentes</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Sesiones Auditadas</div>
      <div class="kpi-val">${{sCount}}</div>
      <div class="kpi-sub">${{DATA.total_scans}} escaneos pasivos + promiscuos</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Tramas 802.11 / PCAP</div>
      <div class="kpi-val">${{DATA.totals.mgmt_frames + DATA.totals.data_frames}}</div>
      <div class="kpi-sub">PCAP: <b style="color:var(--accent)">${{DATA.totals.pcap_frames || 0}}</b> · EAPOL: <b style="color:${{(DATA.totals.eapol_frames || 0) ? 'var(--amber)' : 'var(--muted)'}}">${{DATA.totals.eapol_frames || 0}}</b> · Deauth: <b style="color:${{DATA.totals.deauth_frames ? 'var(--red)' : 'var(--green)'}}">${{DATA.totals.deauth_frames}}</b></div>
    </div>
  `;

  // Canales
  const maxCh = Math.max(1, ...Object.values(DATA.channel_counts));
  let chHtml = "";
  for (let ch = 1; ch <= 13; ch++) {{
    const cnt = DATA.channel_counts[ch] || 0;
    const pct = Math.round((cnt / maxCh) * 100);
    chHtml += `
      <div class="bar-row">
        <div class="bar-label">Canal ${{String(ch).padStart(2, " ")}}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${{pct}}%"></div></div>
        <div class="bar-count">${{cnt}} APs</div>
      </div>`;
  }}
  document.getElementById("chart-channels").innerHTML = chHtml;

  // Seguridad
  const maxSec = Math.max(1, ...Object.values(DATA.auth_counts));
  let secHtml = "";
  Object.entries(DATA.auth_counts).forEach(([k, cnt]) => {{
    const pct = Math.round((cnt / maxSec) * 100);
    const col = (k === "OPEN" || k === "WEP" || k.includes("WPA_PSK")) ? "#f59e0b" : "#10b981";
    secHtml += `
      <div class="bar-row">
        <div class="bar-label" style="width:140px">${{esc(k)}}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${{pct}}%;background:${{col}}"></div></div>
        <div class="bar-count">${{cnt}} APs</div>
      </div>`;
  }});
  document.getElementById("chart-security").innerHTML = secHtml;

  // Findings
  let fHtml = "";
  if (weakAps > 0) {{
    fHtml += `<div class="kv" style="margin-bottom:10px;border-left:3px solid var(--amber)">
      <div class="kv-k" style="color:var(--amber)">RIESGO ALTO · Cifrado Obsoleto o Mixto (WPA1 / TKIP / OPEN)</div>
      <div style="margin-top:4px">Se han detectado <b>${{weakAps}} puntos de acceso</b> que anuncian soporte para TKIP, WPA1 o red abierta. Haz clic en la pestaña <i>Inteligencia de Redes → Cifrado Débil</i> para inspeccionarlos.</div>
    </div>`;
  }}
  if (wpsAps > 0) {{
    fHtml += `<div class="kv" style="margin-bottom:10px;border-left:3px solid var(--accent)">
      <div class="kv-k" style="color:var(--accent)">SUPERFICIE EXPUESTA · WPS Activo en ${{wpsAps}} Puntos de Acceso</div>
      <div style="margin-top:4px">${{wpsAps}} routers exponen Wi-Fi Protected Setup (WPS) en sus balizas 802.11.</div>
    </div>`;
  }}
  if (DATA.ssid_collisions.length > 0) {{
    fHtml += `<div class="kv" style="margin-bottom:10px;border-left:3px solid var(--purple)">
      <div class="kv-k" style="color:#c084fc">INFRAESTRUCTURA MULTI-BSSID / ROAMING / POSIBLE EVIL TWIN</div>
      <div style="margin-top:4px">SSIDs emitidos desde múltiples BSSIDs físicos: ` +
      DATA.ssid_collisions.map(c =>
        `<a class="entity-link mono" onclick="openSsidDossier('${{esc(c.ssid)}}')">${{esc(c.ssid)}} (${{c.bssids.length}} BSSIDs)</a>`
      ).join(" · ") + `</div></div>`;
  }}
  if (!fHtml) {{
    fHtml = `<div class="kv">Sin alertas críticas detectadas en las sesiones actuales.</div>`;
  }}
  document.getElementById("findings-list").innerHTML = fHtml;
}}

function setNetFilter(f, el) {{
  netFilter = f;
  document.querySelectorAll("#net-chips .chip").forEach(c => c.classList.remove("active"));
  if (el) el.classList.add("active");
  renderNetworksTable();
}}

function getApVulnerabilities(ap) {{
  const vulns = [];
  if (ap.auth_mode === "OPEN") {{
    vulns.push({{
      sev: "CRÍTICO",
      color: "var(--red)",
      short: "Red Abierta (Sin cifrado)",
      detail: "Tráfico 802.11 en texto claro (sin autenticación ni cifrado). Permite interceptación pasiva (sniffing de capa 2/3) e inyección/suplantación directa (Evil Twin / MitM)."
    }});
  }}
  if (ap.auth_mode === "WEP" || ap.pairwise_cipher.includes("WEP")) {{
    vulns.push({{
      sev: "CRÍTICO",
      color: "var(--red)",
      short: "Cifrado WEP (RC4 roto)",
      detail: "Utiliza RC4 con vectores de inicialización (IV) de 24 bits. La clave se recupera en minutos mediante ataques estadísticos FMS/PTW (aircrack-ng)."
    }});
  }}
  if (ap.auth_mode === "WPA_PSK") {{
    vulns.push({{
      sev: "ALTO",
      color: "var(--amber)",
      short: "WPA1 PSK obsoleto",
      detail: "Estándar WPA original (2003) obsoleto. Vulnerable a ataques de diccionario sobre el 4-Way Handshake / PMKID y degradación TKIP."
    }});
  }} else if (ap.auth_mode === "WPA_WPA2_PSK") {{
    vulns.push({{
      sev: "MEDIO",
      color: "var(--amber)",
      short: "Modo mixto WPA1/WPA2 habilitado",
      detail: "El AP acepta clientes legacy WPA1 además de WPA2, ampliando la superficie de ataque por downgrade frente a WPA2/WPA3 puro."
    }});
  }}
  if (ap.pairwise_cipher.includes("TKIP") || (ap.group_cipher && ap.group_cipher.includes("TKIP"))) {{
    vulns.push({{
      sev: "ALTO",
      color: "var(--amber)",
      short: "Cifrado TKIP activo (Beck-Tews / ChopChop)",
      detail: "TKIP (RC4 + MIC Michael) está deprecado por el IEEE 802.11-2012. Permite descifrado parcial de paquetes cortos e inyección de QoS (ataques Beck-Tews / Ohigashi-Morii)."
    }});
  }}
  if (ap.wps) {{
    vulns.push({{
      sev: "MEDIO",
      color: "var(--accent)",
      short: "WPS expuesto en baliza",
      detail: "Wi-Fi Protected Setup (WPS) activo. El PIN de 8 dígitos se divide en dos mitades verificadas por separado (11.000 combinaciones máx.) y muchos chipsets son vulnerables a Pixie-Dust offline (reaver / bully)."
    }});
  }}
  if (ap.hidden) {{
    vulns.push({{
      sev: "INFO",
      color: "#c084fc",
      short: "SSID oculto (Cloaking)",
      detail: "Ocultar el SSID no aporta seguridad criptográfica: el nombre real viaja en claro en cada trama Probe Response y Association Request cuando un cliente legítimo se conecta."
    }});
  }}
  return vulns;
}}

function renderNetworksTable() {{
  const q = (document.getElementById("net-search").value || "").trim();
  const sesFilter = document.getElementById("net-session-filter").value;
  const notSesEl = document.getElementById("net-not-session-filter");
  const notSesFilter = notSesEl ? notSesEl.value : "";

  const filtered = DATA.aps.filter(ap => {{
    const tag = getNetworkTag(ap.bssid, ap.ssid);
    const traces = ap.pcap_traces || [];
    if (sesFilter && !ap.sessions.includes(sesFilter)) return false;
    if (notSesFilter && ap.sessions.includes(notSesFilter)) return false;
    if (netFilter === "insecure" && !ap.is_weak && !ap.wps) return false;
    if (netFilter === "pcap" && traces.length === 0) return false;
    if (netFilter === "eapol" && !traces.includes("EAPOL") && !traces.includes("PMKID") && !traces.includes("HANDSHAKE")) return false;
    if (netFilter === "multi" && ap.sessions.length < 2) return false;
    if (netFilter === "clients" && ap.clients.length === 0) return false;
    if (netFilter === "probed" && ap.probing_stas.length === 0) return false;
    if (netFilter === "weak" && !ap.is_weak) return false;
    if (netFilter === "wps" && !ap.wps) return false;
    if (netFilter === "hidden" && !ap.hidden) return false;
    if (netFilter === "tagged" && (!tag || !tag.label)) return false;
    if (netFilter === "untagged" && tag && tag.label) return false;

    return evaluateDslQuery(q, ap, "ap");
  }});

  lastFilteredNetworks = filtered;
  document.getElementById("net-count-label").textContent = `${{filtered.length}} / ${{DATA.aps.length}} BSSIDs`;

  // Banner explicativo cuando se filtra por Redes No Seguras / Cifrado Débil / WPS / Oculto
  const bannerEl = document.getElementById("net-vuln-banner");
  if (["insecure", "weak", "wps", "hidden"].includes(netFilter)) {{
    const cOpenWep = filtered.filter(a => a.auth_mode === "OPEN" || a.auth_mode === "WEP").length;
    const cTkip = filtered.filter(a => a.pairwise_cipher.includes("TKIP") || a.auth_mode.includes("WPA_")).length;
    const cWps = filtered.filter(a => a.wps).length;
    bannerEl.style.display = "block";
    bannerEl.innerHTML = `
      <div class="kv" style="border-left:3px solid var(--red);background:#161b2e">
        <div class="kv-k" style="color:#f87171">DIAGNÓSTICO DE VULNERABILIDADES (${{filtered.length}} REDES SELECCIONADAS)</div>
        <div style="margin-top:6px;display:grid;gap:4px;font-size:12.5px">
          <div>• <b>Cifrado obsoleto WPA1 / TKIP (${{cTkip}} APs):</b> Soporta <code>TKIP</code> o modo mixto <code>WPA_WPA2_PSK</code>. TKIP está deprecado por IEEE 802.11 y permite ataques de recuperación de MIC/inyección (Beck-Tews) además de facilitar ataques de diccionario sobre handshakes WPA1.</div>
          <div>• <b>Superficie WPS activa (${{cWps}} APs):</b> El protocolo WPS permite ataques offline <i>Pixie-Dust</i> o fuerza bruta reducida a 11.000 PINs independientemente de la complejidad de la clave WPA2.</div>
          ${{cOpenWep > 0 ? `<div>• <b>Redes Abiertas / WEP (${{cOpenWep}} APs):</b> Sin confidencialidad de capa 2; captura de tráfico inmediata.</div>` : ""}}
          <div style="color:var(--muted);margin-top:2px">💡 <i>Pasa el ratón sobre la etiqueta roja/ámbar de la columna Seguridad o haz clic en cualquier <b>SSID / BSSID</b> para ver el desglose técnico exacto de esa red.</i></div>
        </div>
      </div>`;
  }} else {{
    bannerEl.style.display = "none";
    bannerEl.innerHTML = "";
  }}

  const rows = filtered.map(ap => {{
    const tag = getNetworkTag(ap.bssid, ap.ssid);
    const vulns = getApVulnerabilities(ap);
    const ssidDisp = ap.hidden
      ? `<span class="badge b-suspicious">&lt;OCULTA&gt;</span>`
      : `<a class="entity-link" onclick="openSsidDossier('${{esc(ap.ssid)}}')">${{esc(ap.ssid)}}</a>`;
    const clusterBadge = ap.cluster_size > 1
      ? ` <span class="badge b-multi" title="Mismo SSID en varios BSSIDs">${{ap.cluster_size}} APs</span>` : "";
    const wpsBadge = ap.wps ? `<span class="badge b-target" title="Wi-Fi Protected Setup expuesto (vulnerable a PIN/Pixie-Dust)">WPS</span>` : `<span style="color:var(--muted)">no</span>`;
    const stasHtml = ap.clients.length > 0
      ? `<a class="entity-link mono" onclick="openApDossier('${{ap.bssid}}')">${{ap.clients.length}} STAs</a>`
      : `<span style="color:var(--muted)">0</span>`;
    const probedHtml = ap.probing_stas.length > 0
      ? `<span class="badge b-known">${{ap.probing_stas.length}} STAs</span>`
      : `<span style="color:var(--muted)">—</span>`;
    const sesBadge = ap.sessions.length >= 2
      ? `<span class="badge b-multi">${{ap.sessions.length}} sesiones</span>`
      : `<span class="mono" style="color:var(--muted)">${{esc(getSessionDisplay(ap.sessions[0] || ""))}}</span>`;

    const secStyle = ap.is_weak ? 'color:#f87171;font-weight:700' : '';
    const vulnReasonsHtml = vulns.length > 0
      ? `<div style="margin-top:3px;font-size:11px;color:#fbbf24">` +
        vulns.map(v => `<span title="${{esc(v.detail)}}">⚠️ ${{esc(v.short)}}</span>`).join(" · ") +
        `</div>`
      : "";

    const wpsModel = ap.wps_info && (ap.wps_info.model_name || ap.wps_info.device_name)
      ? `<div class="mono" style="font-size:11px;color:var(--accent);margin-top:2px">🔍 WPS: ${{esc(ap.wps_info.model_name || ap.wps_info.device_name)}}</div>`
      : "";

    return `<tr>
      <td>${{rssiBar(ap.rssi)}}</td>
      <td class="mono">${{ap.primary_channel}} <span style="color:var(--muted)">(${{ap.band_mhz}})</span></td>
      <td>${{ssidDisp}}${{clusterBadge}}</td>
      <td><a class="entity-link mono" onclick="openApDossier('${{ap.bssid}}')">${{ap.bssid}}</a></td>
      <td>${{renderTagBadge(tag)}}</td>
      <td><span class="mono" style="${{secStyle}}">${{esc(ap.auth_mode)}} / ${{esc(ap.pairwise_cipher)}}</span>${{vulnReasonsHtml}}</td>
      <td>${{wpsBadge}}</td>
      <td>${{renderPcapTracesBadges(ap.pcap_traces, ap.pcap_frames)}}</td>
      <td>${{stasHtml}}</td>
      <td>${{probedHtml}}</td>
      <td>${{sesBadge}}</td>
      <td>${{esc(ap.vendor)}}${{wpsModel}}</td>
      <td class="no-print">
        <button onclick="openTagEditor('network', '${{ap.bssid}}', '${{esc(ap.ssid || ap.bssid)}}')">🏷️ Tag</button>
      </td>
    </tr>`;
  }});

  document.getElementById("net-tbody").innerHTML = rows.join("") ||
    `<tr><td colspan="13" style="text-align:center;color:var(--muted);padding:24px">Sin resultados con los filtros actuales.</td></tr>`;
}}

function setDevFilter(f, el) {{
  devFilter = f;
  document.querySelectorAll("#dev-chips .chip").forEach(c => c.classList.remove("active"));
  if (el) el.classList.add("active");
  renderDevicesTable();
}}

function renderDevicesTable() {{
  const q = (document.getElementById("dev-search").value || "").trim();
  const sesEl = document.getElementById("dev-session-filter");
  const notSesEl = document.getElementById("dev-not-session-filter");
  const sesFilter = sesEl ? sesEl.value : "";
  const notSesFilter = notSesEl ? notSesEl.value : "";

  const filtered = DATA.devices.filter(d => {{
    const tag = getDeviceTag(d.sta_mac);
    const traces = d.pcap_traces || [];
    if (sesFilter && !d.sessions.includes(sesFilter)) return false;
    if (notSesFilter && d.sessions.includes(notSesFilter)) return false;
    if (devFilter === "insecure_ap") {{
      const onInsecure = d.associated_bssids.some(b => {{
        const ap = DATA.ap_by_bssid[b];
        return ap && (ap.is_weak || ap.wps);
      }});
      if (!onInsecure) return false;
    }}
    if (devFilter === "pcap" && traces.length === 0) return false;
    if (devFilter === "eapol" && !traces.includes("EAPOL") && !traces.includes("PMKID") && !traces.includes("HANDSHAKE")) return false;
    if (devFilter === "multi" && d.sessions.length < 2) return false;
    if (devFilter === "associated" && d.associated_bssids.length === 0) return false;
    if (devFilter === "probing" && d.probed_ssids.length === 0) return false;
    if (devFilter === "matched" && d.matched_local_ssids.length === 0) return false;
    if (devFilter === "global_mac" && d.is_randomized) return false;
    if (devFilter === "tagged" && (!tag || !tag.label)) return false;
    if (devFilter === "untagged" && tag && tag.label) return false;

    return evaluateDslQuery(q, d, "device");
  }});

  lastFilteredDevices = filtered;
  document.getElementById("dev-count-label").textContent = `${{filtered.length}} / ${{DATA.devices.length}} dispositivos`;

  const rows = filtered.map(d => {{
    const tag = getDeviceTag(d.sta_mac);
    const fpBadge = d.ie_fingerprint
      ? ` <span class="badge b-multi mono" title="Huella de radio IE-Fingerprint en Probe Requests (permite correlacionar MACs aleatorias)" style="cursor:pointer" onclick="document.getElementById('dev-search').value='fp:${{d.ie_fingerprint}}';renderDevicesTable()">🧬 ${{esc(d.ie_fingerprint)}}</span>`
      : "";
    const macType = (d.is_randomized
      ? `<span class="badge b-neutral" title="Bit Locally-Administered activo">MAC Aleatoria</span>`
      : `<span class="badge b-own" title="OUI IEEE global">${{esc(d.vendor)}}</span>`) + fpBadge;

    const assocHtml = d.associated_bssids.length > 0
      ? d.associated_bssids.map(b => {{
          const ap = DATA.ap_by_bssid[b];
          const s = ap && ap.ssid ? ap.ssid : b;
          return `<a class="entity-link mono" onclick="openApDossier('${{b}}')">${{esc(s)}}</a>`;
        }}).join(", ")
      : `<span style="color:var(--muted)">Sin asociar (solo Probe)</span>`;

    const probesHtml = d.probed_ssids.length > 0
      ? d.probed_ssids.map(ssid => {{
          const existsHere = DATA.matched_ssids_set.includes(ssid);
          const cls = existsHere ? "b-target" : "b-known";
          const title = existsHere ? "Esta red está presente en el entorno" : "Red remota en la PNL del dispositivo";
          return `<span class="badge ${{cls}}" title="${{title}}" style="cursor:pointer" onclick="openSsidDossier('${{esc(ssid)}}')">${{esc(ssid)}}</span>`;
        }}).join(" ")
      : `<span style="color:var(--muted)">— (Broadcast / Datos)</span>`;

    const sesHtml = d.sessions.length >= 2
      ? `<span class="badge b-multi">${{d.sessions.length}} sesiones</span>`
      : `<span class="mono" style="color:var(--muted)">${{esc(getSessionDisplay(d.sessions[0] || ""))}}</span>`;

    return `<tr>
      <td>${{rssiBar(d.rssi)}}</td>
      <td><a class="entity-link mono" onclick="openDeviceDossier('${{d.sta_mac}}')">${{d.sta_mac}}</a></td>
      <td>${{renderTagBadge(tag)}}</td>
      <td>${{macType}}</td>
      <td>${{assocHtml}}</td>
      <td>${{probesHtml}}</td>
      <td>${{renderPcapTracesBadges(d.pcap_traces, d.pcap_frames)}}</td>
      <td class="mono">${{d.total_frames}}</td>
      <td>${{sesHtml}}</td>
      <td class="no-print">
        <button onclick="openTagEditor('device', '${{d.sta_mac}}', '${{d.sta_mac}}')">🏷️ Tag</button>
      </td>
    </tr>`;
  }});

  document.getElementById("dev-tbody").innerHTML = rows.join("") ||
    `<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:24px">Todavía no hay dispositivos clientes que coincidan con este filtro. Deja correr el modo promiscuo unos ciclos y ejecuta <code>warpull</code>.</td></tr>`;
}}

function toggleSetSession(grp, sid) {{
  const arr = setAlgState[grp];
  const idx = arr.indexOf(sid);
  if (idx >= 0) arr.splice(idx, 1);
  else arr.push(sid);
  renderCrossSession();
}}

function setAlgebraOp(op) {{
  setAlgState.op = op;
  renderCrossSession();
}}

function setAlgebraEntity(ent) {{
  setAlgState.entity = ent;
  renderCrossSession();
}}

function computeSetAlgebraResults() {{
  const A = new Set(setAlgState.groupA);
  const B = new Set(setAlgState.groupB);
  const op = setAlgState.op;

  function checkMembership(itemSessions) {{
    const inA = itemSessions.some(s => A.has(s));
    const inB = itemSessions.some(s => B.has(s));
    if (op === "diff_ab") return inA && !inB;        // A \ B
    if (op === "diff_ba") return inB && !inA;        // B \ A
    if (op === "inter")   return inA && inB;         // A ∩ B
    if (op === "symdiff") return (inA && !inB) || (inB && !inA); // A Δ B
    if (op === "union")   return inA || inB;         // A ∪ B
    return false;
  }}

  if (setAlgState.entity === "devices") {{
    return DATA.devices.filter(d => checkMembership(d.sessions));
  }}
  if (setAlgState.entity === "aps") {{
    return DATA.aps.filter(a => checkMembership(a.sessions));
  }}
  // Huellas PNL (SSIDs buscados por clientes)
  const ssidSessions = {{}};
  DATA.devices.forEach(d => {{
    (d.probed_ssids || []).forEach(ssid => {{
      if (!ssidSessions[ssid]) ssidSessions[ssid] = new Set();
      d.sessions.forEach(s => ssidSessions[ssid].add(s));
    }});
  }});
  return Object.entries(ssidSessions)
    .filter(([_, sSet]) => checkMembership(Array.from(sSet)))
    .map(([ssid, sSet]) => ({{ ssid, sessions: Array.from(sSet) }}));
}}

function renderCrossSession() {{
  if (!setAlgState.initialized && DATA.sessions.length > 0) {{
    setAlgState.initialized = true;
    setAlgState.groupA = [DATA.sessions[DATA.sessions.length - 1].session_id];
    if (DATA.sessions.length >= 2) {{
      setAlgState.groupB = [DATA.sessions[0].session_id];
    }}
  }}

  const sesButtonsA = DATA.sessions.map(s => {{
    const active = setAlgState.groupA.includes(s.session_id);
    return `<span class="chip ${{active ? 'active' : ''}}" onclick="toggleSetSession('groupA','${{s.session_id}}')">${{esc(getSessionDisplay(s.session_id))}}</span>`;
  }}).join(" ");

  const sesButtonsB = DATA.sessions.map(s => {{
    const active = setAlgState.groupB.includes(s.session_id);
    return `<span class="chip ${{active ? 'active' : ''}}" onclick="toggleSetSession('groupB','${{s.session_id}}')">${{esc(getSessionDisplay(s.session_id))}}</span>`;
  }}).join(" ");

  const results = computeSetAlgebraResults();
  const opLabels = {{
    diff_ab: "A \\\\ B — Presentes en A pero NO en B (Nuevos / Intrusos respecto a B)",
    diff_ba: "B \\\\ A — Presentes en B pero NO en A (Desaparecidos en A)",
    inter:   "A ∩ B — Intersección (Co-presentes tanto en A como en B)",
    symdiff: "A Δ B — Diferencia Simétrica (Exclusivos de A o de B, nunca en ambos)",
    union:   "A ∪ B — Unión de los conjuntos seleccionados",
  }};

  let html = `
    <div class="kv" style="margin-bottom:18px;border:1px solid var(--border-hi);background:#0c1324">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px">
        <div>
          <span class="brand-badge">ÁLGEBRA DE CONJUNTOS ENTRE SESIONES</span>
          <span style="margin-left:8px;font-weight:700;color:#f8fafc">Comparador Diferencial de Entornos (A vs B)</span>
        </div>
        <div class="chip-group">
          <span class="chip ${{setAlgState.entity === 'devices' ? 'active' : ''}}" onclick="setAlgebraEntity('devices')">📱 Dispositivos (STAs)</span>
          <span class="chip ${{setAlgState.entity === 'aps' ? 'active' : ''}}" onclick="setAlgebraEntity('aps')">📡 Redes (BSSIDs)</span>
          <span class="chip ${{setAlgState.entity === 'pnl' ? 'active' : ''}}" onclick="setAlgebraEntity('pnl')">🔍 Redes Buscadas (PNL)</span>
        </div>
      </div>

      <div class="grid-2" style="margin-bottom:12px">
        <div class="kv">
          <div class="kv-k" style="color:var(--accent);margin-bottom:6px">CONJUNTO A (Sesiones Objetivo / Actual): ${{setAlgState.groupA.length}} sel.</div>
          <div class="chip-group">${{sesButtonsA || '<span style="color:var(--muted)">Sin sesiones</span>'}}</div>
        </div>
        <div class="kv">
          <div class="kv-k" style="color:#c084fc;margin-bottom:6px">CONJUNTO B (Sesiones Línea Base / Comparación): ${{setAlgState.groupB.length}} sel.</div>
          <div class="chip-group">${{sesButtonsB || '<span style="color:var(--muted)">Sin sesiones</span>'}}</div>
        </div>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
        <div class="chip-group">
          <span class="chip ${{setAlgState.op === 'diff_ab' ? 'active' : ''}}" onclick="setAlgebraOp('diff_ab')"><b>A \\\\ B</b> (En A y NO en B)</span>
          <span class="chip ${{setAlgState.op === 'diff_ba' ? 'active' : ''}}" onclick="setAlgebraOp('diff_ba')"><b>B \\\\ A</b> (En B y NO en A)</span>
          <span class="chip ${{setAlgState.op === 'inter' ? 'active' : ''}}" onclick="setAlgebraOp('inter')"><b>A ∩ B</b> (Comunes a A y B)</span>
          <span class="chip ${{setAlgState.op === 'symdiff' ? 'active' : ''}}" onclick="setAlgebraOp('symdiff')"><b>A Δ B</b> (Exclusivos)</span>
          <span class="chip ${{setAlgState.op === 'union' ? 'active' : ''}}" onclick="setAlgebraOp('union')"><b>A ∪ B</b> (Unión)</span>
        </div>
        ${{setAlgState.entity !== 'pnl' && results.length > 0 ? `<button onclick="bulkTagSetResults()">🏷️ Etiquetar los ${{results.length}} resultados</button>` : ""}}
      </div>
    </div>

    <h4 style="margin-top:0">Resultado de <code>${{esc(opLabels[setAlgState.op])}}</code>: <span style="color:var(--accent)">${{results.length}} coincidencias</span></h4>
  `;

  if (results.length === 0) {{
    html += `<div class="kv" style="margin-bottom:22px;color:var(--muted)">El conjunto resultante está vacío para la operación seleccionada.</div>`;
  }} else if (setAlgState.entity === "devices") {{
    html += `<table><thead><tr><th>STA MAC</th><th>Tag</th><th>Fabricante / IE-Fingerprint</th><th>RSSI</th><th>Trazas PCAP</th><th>Sesiones</th><th>APs / Redes Buscadas</th></tr></thead><tbody>`;
    results.forEach(d => {{
      const fp = d.ie_fingerprint ? ` <span class="badge b-multi mono">🧬 ${{esc(d.ie_fingerprint)}}</span>` : "";
      html += `<tr>
        <td><a class="entity-link mono" onclick="openDeviceDossier('${{d.sta_mac}}')">${{d.sta_mac}}</a></td>
        <td>${{renderTagBadge(getDeviceTag(d.sta_mac))}}</td>
        <td>${{esc(d.vendor)}}${{fp}}</td>
        <td>${{rssiBar(d.rssi)}}</td>
        <td>${{renderPcapTracesBadges(d.pcap_traces, d.pcap_frames)}}</td>
        <td>${{d.sessions.map(s => `<span class="badge b-known">${{esc(getSessionDisplay(s))}}</span>`).join(" ")}}</td>
        <td>${{[...d.associated_ssids, ...d.probed_ssids].map(esc).join(", ") || "—"}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }} else if (setAlgState.entity === "aps") {{
    html += `<table><thead><tr><th>BSSID</th><th>SSID</th><th>Tag</th><th>CH</th><th>RSSI</th><th>Seguridad</th><th>Trazas PCAP</th><th>Sesiones</th></tr></thead><tbody>`;
    results.forEach(ap => {{
      html += `<tr>
        <td><a class="entity-link mono" onclick="openApDossier('${{ap.bssid}}')">${{ap.bssid}}</a></td>
        <td><b>${{ap.hidden ? "&lt;OCULTA&gt;" : esc(ap.ssid)}}</b></td>
        <td>${{renderTagBadge(getNetworkTag(ap.bssid, ap.ssid))}}</td>
        <td class="mono">${{ap.primary_channel}}</td>
        <td>${{rssiBar(ap.rssi)}}</td>
        <td class="mono">${{esc(ap.auth_mode)}}/${{esc(ap.pairwise_cipher)}}</td>
        <td>${{renderPcapTracesBadges(ap.pcap_traces, ap.pcap_frames)}}</td>
        <td>${{ap.sessions.map(s => `<span class="badge b-known">${{esc(getSessionDisplay(s))}}</span>`).join(" ")}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }} else {{
    html += `<table><thead><tr><th>SSID Buscado (PNL)</th><th>Presente en el entorno</th><th>Sesiones donde se buscó</th></tr></thead><tbody>`;
    results.forEach(r => {{
      const local = DATA.matched_ssids_set.includes(r.ssid);
      html += `<tr>
        <td><a class="entity-link mono" onclick="openSsidDossier('${{esc(r.ssid)}}')">${{esc(r.ssid)}}</a></td>
        <td>${{local ? '<span class="badge b-target">SÍ (AP local)</span>' : '<span class="badge b-neutral">No (Remota)</span>'}}</td>
        <td>${{r.sessions.map(s => `<span class="badge b-known">${{esc(getSessionDisplay(s))}}</span>`).join(" ")}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  const multiDevs = DATA.devices.filter(d => d.sessions.length >= 2);
  const multiAps = DATA.aps.filter(a => a.sessions.length >= 2);

  html += `<h4 style="margin-top:28px">Resumen Global — Dispositivos Clientes Recurrentes (&ge;2 Sesiones: ${{multiDevs.length}})</h4>`;
  if (multiDevs.length === 0) {{
    html += `<div class="kv" style="margin-bottom:18px;color:var(--muted)">Ningún cliente STA ha repetido en más de una sesión todavía.</div>`;
  }} else {{
    html += `<table><thead><tr><th>STA MAC</th><th>Tag</th><th>Fabricante / Tipo</th><th>Sesiones donde apareció</th><th>Redes Buscadas / Asociadas</th></tr></thead><tbody>`;
    multiDevs.forEach(d => {{
      html += `<tr>
        <td><a class="entity-link mono" onclick="openDeviceDossier('${{d.sta_mac}}')">${{d.sta_mac}}</a></td>
        <td>${{renderTagBadge(getDeviceTag(d.sta_mac))}}</td>
        <td>${{esc(d.vendor)}}</td>
        <td>${{d.sessions.map(s => `<span class="badge b-multi">${{esc(getSessionDisplay(s))}}</span>`).join(" ")}}</td>
        <td>${{[...d.associated_ssids, ...d.probed_ssids].map(esc).join(", ") || "—"}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  html += `<h4 style="margin-top:24px">Puntos de Acceso Presentes en Múltiples Sesiones (${{multiAps.length}})</h4>`;
  html += `<table><thead><tr><th>BSSID</th><th>SSID</th><th>Tag</th><th>CH</th><th>RSSI Máx</th><th>Sesiones</th></tr></thead><tbody>`;
  multiAps.forEach(ap => {{
    html += `<tr>
      <td><a class="entity-link mono" onclick="openApDossier('${{ap.bssid}}')">${{ap.bssid}}</a></td>
      <td><b>${{ap.hidden ? "&lt;OCULTA&gt;" : esc(ap.ssid)}}</b></td>
      <td>${{renderTagBadge(getNetworkTag(ap.bssid, ap.ssid))}}</td>
      <td class="mono">${{ap.primary_channel}}</td>
      <td>${{rssiBar(ap.rssi)}}</td>
      <td>${{ap.sessions.map(s => `<span class="badge b-known">${{esc(getSessionDisplay(s))}}</span>`).join(" ")}}</td>
    </tr>`;
  }});
  html += `</tbody></table>`;

  document.getElementById("cross-content").innerHTML = html;
}}

function renderSessionsTable() {{
  const optsHtml = DATA.sessions.map(s => `<option value="${{s.session_id}}">${{esc(getSessionDisplay(s.session_id))}}</option>`).join("");
  const populateSelect = (id, firstLabel) => {{
    const el = document.getElementById(id);
    if (!el) return;
    const cur = el.value;
    el.innerHTML = `<option value="">${{firstLabel}}</option>` + optsHtml;
    el.value = cur;
  }};
  populateSelect("net-session-filter", `En sesión: Todas (${{DATA.sessions.length}})`);
  populateSelect("net-not-session-filter", "Excluir sesión: Ninguna");
  populateSelect("dev-session-filter", `En sesión: Todas (${{DATA.sessions.length}})`);
  populateSelect("dev-not-session-filter", "Excluir sesión: Ninguna");

  const rows = DATA.sessions.map(s => {{
    const st = getSessionTag(s.session_id);
    const gps = st.gps || s.gps;
    const gpsHtml = (gps && gps.lat !== undefined && gps.lat !== null)
      ? `<a class="entity-link mono" target="_blank" href="https://www.openstreetmap.org/?mlat=${{gps.lat}}&mlon=${{gps.lon}}#map=17/${{gps.lat}}/${{gps.lon}}">📍 ${{Number(gps.lat).toFixed(5)}}, ${{Number(gps.lon).toFixed(5)}}</a>`
      : `<span style="color:var(--muted)">Sin fijar</span>`;

    const matchingPcap = (DATA.pcap_files || []).find(pf => pf.includes(s.session_id));
    const pcapHtml = matchingPcap
      ? (window.location.protocol.startsWith("http")
          ? `<a class="entity-link mono" href="/export/pcap/${{encodeURIComponent(matchingPcap)}}">📦 ${{esc(matchingPcap)}}</a>`
          : `<span class="badge b-known mono">📦 ${{esc(matchingPcap)}}</span>`)
      : `<span style="color:var(--muted)">—</span>`;

    return `<tr>
      <td class="mono"><b>${{s.session_id}}</b></td>
      <td>${{st.name ? `<span class="badge b-own">${{esc(st.name)}}</span>` : '<span style="color:var(--muted)">Sin nombre</span>'}}</td>
      <td class="mono">${{esc(s.file)}}</td>
      <td class="mono">${{esc(s.first_seen)}} → ${{esc(s.last_seen)}}</td>
      <td class="mono">${{s.scans}}</td>
      <td class="mono">${{s.unique_aps}}</td>
      <td class="mono">${{s.unique_clients}}</td>
      <td>${{pcapHtml}}</td>
      <td>${{gpsHtml}}</td>
      <td class="no-print">
        <button onclick="openSessionEditor('${{s.session_id}}')">✏️ Nombrar / GPS</button>
      </td>
    </tr>`;
  }});
  document.getElementById("sessions-tbody").innerHTML = rows.join("");
}}

function renderTagsRegistry() {{
  let html = `<h4>Sesiones Nombradas</h4><table><thead><tr><th>Session ID</th><th>Nombre</th><th>GPS Asociado</th><th>Notas</th><th>Acción</th></tr></thead><tbody>`;
  const sEntries = Object.entries(TAGS.sessions);
  if (sEntries.length === 0) {{
    html += `<tr><td colspan="5" style="color:var(--muted)">Sin sesiones etiquetadas aún.</td></tr>`;
  }} else {{
    sEntries.forEach(([sid, info]) => {{
      const gpsTxt = info.gps && info.gps.lat !== undefined ? `${{info.gps.lat}}, ${{info.gps.lon}}` : "—";
      html += `<tr>
        <td class="mono">${{esc(sid)}}</td>
        <td><b>${{esc(info.name || "—")}}</b></td>
        <td class="mono">${{esc(gpsTxt)}}</td>
        <td>${{esc(info.notes || "")}}</td>
        <td><button onclick="deleteTag('sessions','${{esc(sid)}}')">🗑️ Borrar</button></td>
      </tr>`;
    }});
  }}
  html += `</tbody></table>`;

  html += `<h4 style="margin-top:20px">Redes Etiquetadas (BSSID / SSID)</h4><table><thead><tr><th>Clave</th><th>Etiqueta / Alias</th><th>Categoría</th><th>Notas</th><th>Acción</th></tr></thead><tbody>`;
  const nEntries = Object.entries(TAGS.networks);
  if (nEntries.length === 0) {{
    html += `<tr><td colspan="5" style="color:var(--muted)">Sin redes etiquetadas aún.</td></tr>`;
  }} else {{
    nEntries.forEach(([k, info]) => {{
      html += `<tr>
        <td class="mono">${{esc(k)}}</td>
        <td>${{renderTagBadge(info)}}</td>
        <td class="mono">${{esc(info.category || "")}}</td>
        <td>${{esc(info.notes || "")}}</td>
        <td><button onclick="deleteTag('networks','${{esc(k)}}')">🗑️ Borrar</button></td>
      </tr>`;
    }});
  }}
  html += `</tbody></table>`;

  html += `<h4 style="margin-top:20px">Dispositivos Etiquetados (STA MAC)</h4><table><thead><tr><th>STA MAC</th><th>Etiqueta / Alias</th><th>Categoría</th><th>Notas</th><th>Acción</th></tr></thead><tbody>`;
  const dEntries = Object.entries(TAGS.devices);
  if (dEntries.length === 0) {{
    html += `<tr><td colspan="5" style="color:var(--muted)">Sin dispositivos etiquetados aún.</td></tr>`;
  }} else {{
    dEntries.forEach(([k, info]) => {{
      html += `<tr>
        <td class="mono">${{esc(k)}}</td>
        <td>${{renderTagBadge(info)}}</td>
        <td class="mono">${{esc(info.category || "")}}</td>
        <td>${{esc(info.notes || "")}}</td>
        <td><button onclick="deleteTag('devices','${{esc(k)}}')">🗑️ Borrar</button></td>
      </tr>`;
    }});
  }}
  html += `</tbody></table>`;

  document.getElementById("tags-registry-content").innerHTML = html;
}}

function deleteTag(group, key) {{
  delete TAGS[group][key];
  saveTags();
}}

/* ---------------- DOSSIERS INTERACTIVOS ---------------- */

function openApDossier(bssid) {{
  const ap = DATA.ap_by_bssid[bssid];
  if (!ap) return;
  const tag = getNetworkTag(ap.bssid, ap.ssid);
  const stas = ap.clients.map(mac => DATA.device_by_mac[mac]).filter(Boolean);

  let html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge" style="display:inline-block;margin-bottom:6px">DOSSIER DE PUNTO DE ACCESO (BSSID)</div>
        <h2 style="margin:0">${{ap.hidden ? "&lt;RED OCULTA&gt;" : esc(ap.ssid)}} <span class="mono" style="color:var(--accent)">(${{ap.bssid}})</span></h2>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="openTagEditor('network', '${{ap.bssid}}', '${{esc(ap.ssid || ap.bssid)}}')">🏷️ Etiquetar AP</button>
        <button onclick="closeModal()">✕ Cerrar</button>
      </div>
    </div>
    <div class="kv-grid">
      <div class="kv"><div class="kv-k">Tag / Identidad</div><div class="kv-v">${{renderTagBadge(tag)}}</div></div>
      <div class="kv"><div class="kv-k">Fabricante (OUI)</div><div class="kv-v">${{esc(ap.vendor)}}</div></div>
      <div class="kv"><div class="kv-k">Canal / Ancho</div><div class="kv-v">CH ${{ap.primary_channel}} (${{ap.band_mhz}} MHz · ${{ap.proto}})</div></div>
      <div class="kv"><div class="kv-k">Seguridad / Cifrado</div><div class="kv-v">${{esc(ap.auth_mode)}} / ${{esc(ap.pairwise_cipher)}}</div></div>
      <div class="kv"><div class="kv-k">WPS / Oculta</div><div class="kv-v">WPS: ${{ap.wps ? "SÍ" : "NO"}} · Oculta: ${{ap.hidden ? "SÍ" : "NO"}}</div></div>
      <div class="kv"><div class="kv-k">Señal Máx / Visto</div><div class="kv-v">${{ap.rssi}} dBm (${{ap.sightings}} veces)</div></div>
      <div class="kv"><div class="kv-k">Trazas en PCAP</div><div class="kv-v">${{renderPcapTracesBadges(ap.pcap_traces, ap.pcap_frames)}}</div></div>
      ${{ap.wps_info && Object.keys(ap.wps_info).length > 0 ? `<div class="kv"><div class="kv-k">Hardware WPS (PCAP)</div><div class="kv-v">${{esc([ap.wps_info.manufacturer, ap.wps_info.model_name, ap.wps_info.model_number, ap.wps_info.device_name].filter(Boolean).join(" · "))}}</div></div>` : ""}}
      ${{ap.eapol_msgs && ap.eapol_msgs.length > 0 ? `<div class="kv"><div class="kv-k">Mensajes EAPOL Vistos</div><div class="kv-v" style="color:var(--amber)">${{esc(ap.eapol_msgs.join(", "))}}</div></div>` : ""}}
      ${{ap.deauth_reasons && ap.deauth_reasons.length > 0 ? `<div class="kv"><div class="kv-k">Razones Deauth (IEEE)</div><div class="kv-v" style="color:var(--red)">${{esc(ap.deauth_reasons.join(", "))}}</div></div>` : ""}}
    </div>
    <h4>Evaluación de Seguridad y Vulnerabilidades Detectadas</h4>
    ${{(() => {{
      const vulns = getApVulnerabilities(ap);
      if (vulns.length === 0) {{
        return `<div class="kv" style="margin-bottom:16px;border-left:3px solid var(--green)"><b style="color:var(--green)">✓ Configuracion robusta:</b> Autenticación ${{esc(ap.auth_mode)}} con cifrado ${{esc(ap.pairwise_cipher)}} puro y WPS deshabilitado.</div>`;
      }}
      return `<div style="display:grid;gap:8px;margin-bottom:16px">` + vulns.map(v => `
        <div class="kv" style="border-left:3px solid ${{v.color}}">
          <div class="kv-k" style="color:${{v.color}}">SEVERIDAD ${{esc(v.sev)}} · ${{esc(v.short)}}</div>
          <div style="margin-top:4px;font-size:12.8px">${{esc(v.detail)}}</div>
        </div>
      `).join("") + `</div>`;
    }})()}}
    <h4>Sesiones donde se detectó (${{ap.sessions.length}})</h4>
    <div style="margin-bottom:16px">${{ap.sessions.map(s => `<span class="badge b-known" style="margin-right:6px">${{esc(getSessionDisplay(s))}}</span>`).join("")}}</div>
    <h4>Estaciones Clientes Asociadas a este BSSID (${{stas.length}})</h4>
  `;

  if (stas.length === 0) {{
    html += `<div class="kv" style="color:var(--muted)">No se han capturado tramas de datos de clientes asociados a este BSSID todavía.</div>`;
  }} else {{
    html += `<table><thead><tr><th>STA MAC</th><th>Tag</th><th>Fabricante</th><th>RSSI</th><th>Redes que busca (PNL)</th></tr></thead><tbody>`;
    stas.forEach(d => {{
      html += `<tr>
        <td><a class="entity-link mono" onclick="openDeviceDossier('${{d.sta_mac}}')">${{d.sta_mac}}</a></td>
        <td>${{renderTagBadge(getDeviceTag(d.sta_mac))}}</td>
        <td>${{esc(d.vendor)}}</td>
        <td>${{d.rssi}} dBm</td>
        <td>${{d.probed_ssids.map(esc).join(", ") || "—"}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  showModal(html);
}}

function openSsidDossier(ssid) {{
  const matchingAps = DATA.aps.filter(a => a.ssid === ssid);
  const probingDevs = DATA.devices.filter(d => d.probed_ssids.includes(ssid));
  const ssidVulns = [];
  const seenShorts = new Set();
  matchingAps.forEach(ap => {{
    getApVulnerabilities(ap).forEach(v => {{
      if (!seenShorts.has(v.short)) {{
        seenShorts.add(v.short);
        ssidVulns.push(v);
      }}
    }});
  }});

  let html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge" style="display:inline-block;margin-bottom:6px">DOSSIER DE RED (SSID CLUSTER)</div>
        <h2 style="margin:0">${{esc(ssid)}}</h2>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="openTagEditor('network', 'SSID:${{esc(ssid)}}', '${{esc(ssid)}}')">🏷️ Etiquetar SSID</button>
        <button onclick="closeModal()">✕ Cerrar</button>
      </div>
    </div>
    ${{matchingAps.length > 0 ? `
      <h4>Diagnóstico de Seguridad de la Red "${{esc(ssid)}}"</h4>
      ${{ssidVulns.length === 0
        ? `<div class="kv" style="margin-bottom:14px;border-left:3px solid var(--green)"><b style="color:var(--green)">✓ Red segura:</b> Sin debilidades protocolarias detectadas (CCMP puro, sin WPS).</div>`
        : `<div style="display:grid;gap:8px;margin-bottom:14px">` + ssidVulns.map(v => `
            <div class="kv" style="border-left:3px solid ${{v.color}}">
              <div class="kv-k" style="color:${{v.color}}">SEVERIDAD ${{esc(v.sev)}} · ${{esc(v.short)}}</div>
              <div style="margin-top:4px;font-size:12.8px">${{esc(v.detail)}}</div>
            </div>`).join("") + `</div>`
      }}
    ` : ""}}
    <h4>Puntos de Acceso (BSSIDs) que emiten este SSID (${{matchingAps.length}})</h4>
  `;

  if (matchingAps.length === 0) {{
    html += `<div class="kv" style="margin-bottom:14px;color:var(--amber)">Esta red NO está presente físicamente en el entorno, pero ha sido solicitada por dispositivos cercanos mediante Probe Requests (red remota guardada en sus perfiles).</div>`;
  }} else {{
    html += `<table><thead><tr><th>BSSID</th><th>Canal</th><th>RSSI</th><th>Seguridad</th><th>Fabricante</th><th>Clientes</th></tr></thead><tbody>`;
    matchingAps.forEach(ap => {{
      html += `<tr>
        <td><a class="entity-link mono" onclick="openApDossier('${{ap.bssid}}')">${{ap.bssid}}</a></td>
        <td class="mono">${{ap.primary_channel}}</td>
        <td>${{ap.rssi}} dBm</td>
        <td class="mono">${{esc(ap.auth_mode)}}/${{esc(ap.pairwise_cipher)}}</td>
        <td>${{esc(ap.vendor)}}</td>
        <td class="mono">${{ap.clients.length}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  html += `<h4 style="margin-top:18px">Dispositivos que buscan "${{esc(ssid)}}" en Probe Requests (${{probingDevs.length}})</h4>`;
  if (probingDevs.length === 0) {{
    html += `<div class="kv" style="color:var(--muted)">Ningún cliente ha emitido un Probe Request dirigido hacia este SSID durante la escucha.</div>`;
  }} else {{
    html += `<table><thead><tr><th>STA MAC</th><th>Tag</th><th>Fabricante</th><th>RSSI</th><th>Otros SSIDs que busca</th></tr></thead><tbody>`;
    probingDevs.forEach(d => {{
      html += `<tr>
        <td><a class="entity-link mono" onclick="openDeviceDossier('${{d.sta_mac}}')">${{d.sta_mac}}</a></td>
        <td>${{renderTagBadge(getDeviceTag(d.sta_mac))}}</td>
        <td>${{esc(d.vendor)}}</td>
        <td>${{d.rssi}} dBm</td>
        <td>${{d.probed_ssids.filter(x => x !== ssid).map(esc).join(", ") || "—"}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  showModal(html);
}}

function openDeviceDossier(mac) {{
  const d = DATA.device_by_mac[mac];
  if (!d) return;
  const tag = getDeviceTag(d.sta_mac);

  let html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge" style="display:inline-block;margin-bottom:6px">DOSSIER DE DISPOSITIVO CLIENTE (STA)</div>
        <h2 class="mono" style="margin:0">${{d.sta_mac}}</h2>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="openTagEditor('device', '${{d.sta_mac}}', '${{d.sta_mac}}')">🏷️ Etiquetar Dispositivo</button>
        <button onclick="closeModal()">✕ Cerrar</button>
      </div>
    </div>
    <div class="kv-grid">
      <div class="kv"><div class="kv-k">Nombre / Tag</div><div class="kv-v">${{renderTagBadge(tag)}}</div></div>
      <div class="kv"><div class="kv-k">Tipo MAC / OUI</div><div class="kv-v">${{d.is_randomized ? "MAC Aleatoria (Privacidad)" : esc(d.vendor)}}</div></div>
      <div class="kv"><div class="kv-k">Señal Máx / Canal</div><div class="kv-v">${{d.rssi}} dBm (CH ${{d.channel}})</div></div>
      <div class="kv"><div class="kv-k">Tramas Capturadas</div><div class="kv-v">${{d.total_frames}} tramas</div></div>
      <div class="kv"><div class="kv-k">Trazas en PCAP</div><div class="kv-v">${{renderPcapTracesBadges(d.pcap_traces, d.pcap_frames)}}</div></div>
      ${{d.ie_fingerprint ? `<div class="kv"><div class="kv-k">Huella IE-Fingerprint</div><div class="kv-v" style="color:#c084fc">🧬 ${{esc(d.ie_fingerprint)}}</div></div>` : ""}}
      <div class="kv"><div class="kv-k">Persistencia</div><div class="kv-v">${{d.sessions.length}} sesiones (${{d.sessions.map(getSessionDisplay).map(esc).join(", ")}})</div></div>
    </div>
    <h4>Puntos de Acceso a los que se ha asociado (${{d.associated_bssids.length}})</h4>
  `;

  if (d.associated_bssids.length === 0) {{
    html += `<div class="kv" style="margin-bottom:14px;color:var(--muted)">No se le ha visto asociado transmitiendo datos con ningún AP; detectado únicamente por emisiones de Probe Request.</div>`;
  }} else {{
    html += `<table><thead><tr><th>BSSID</th><th>SSID</th><th>Canal</th><th>Seguridad</th><th>Fabricante AP</th></tr></thead><tbody>`;
    d.associated_bssids.forEach(b => {{
      const ap = DATA.ap_by_bssid[b];
      html += `<tr>
        <td><a class="entity-link mono" onclick="openApDossier('${{b}}')">${{b}}</a></td>
        <td><b>${{ap ? (ap.hidden ? "&lt;OCULTA&gt;" : esc(ap.ssid)) : "AP Externo"}}</b></td>
        <td class="mono">${{ap ? ap.primary_channel : "—"}}</td>
        <td class="mono">${{ap ? esc(ap.auth_mode) : "—"}}</td>
        <td>${{ap ? esc(ap.vendor) : "—"}}</td>
      </tr>`;
    }});
    html += `</tbody></table>`;
  }}

  html += `<h4 style="margin-top:18px">Huella PNL — Redes que este dispositivo busca (${{d.probed_ssids.length}})</h4>`;
  if (d.probed_ssids.length === 0) {{
    html += `<div class="kv" style="color:var(--muted)">Solo ha emitido Probe Requests broadcast (wildcard) o tráfico de datos.</div>`;
  }} else {{
    html += `<div style="display:flex;gap:8px;flex-wrap:wrap">` +
      d.probed_ssids.map(s => {{
        const local = DATA.matched_ssids_set.includes(s);
        return `<span class="badge ${{local ? 'b-target' : 'b-known'}}" style="cursor:pointer;padding:6px 10px" onclick="openSsidDossier('${{esc(s)}}')">${{esc(s)}} ${{local ? '(Presente aquí)' : '(Red remota)'}}</span>`;
      }}).join("") + `</div>`;
  }}

  showModal(html);
}}

/* ---------------- EDITORES DE TAGS Y SESIONES ---------------- */

function openTagEditor(targetType, key, displayTitle) {{
  const group = targetType === "device" ? "devices" : "networks";
  const cur = TAGS[group][key.toUpperCase()] || TAGS[group][key] || {{ label: "", category: "CONOCIDO", notes: "" }};
  const normKey = key.startsWith("SSID:") ? key : key.toUpperCase();

  const html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge">ETIQUETAR ENTIDAD</div>
        <h3 style="margin:6px 0 0 0">${{esc(displayTitle)}} <span class="mono" style="color:var(--muted)">(${{esc(normKey)}})</span></h3>
      </div>
      <button onclick="closeModal()">✕</button>
    </div>
    <div style="display:grid;gap:12px">
      <label>Nombre personalizado / Alias (ej. "Mi Móvil", "Router Vecino", "Portátil Auditoría"):<br>
        <input type="text" id="tag-label" value="${{esc(cur.label || "")}}" style="width:100%;margin-top:4px" placeholder="Escribe un alias...">
      </label>
      <label>Categoría:<br>
        <select id="tag-cat" style="width:100%;margin-top:4px">
          ${{["PROPIO", "CONOCIDO", "OBJETIVO", "SOSPECHOSO", "IGNORAR"].map(c =>
            `<option value="${{c}}" ${{cur.category === c ? "selected" : ""}}>${{c}}</option>`
          ).join("")}}
        </select>
      </label>
      <label>Notas de inteligencia:<br>
        <textarea id="tag-notes" rows="3" style="width:100%;margin-top:4px">${{esc(cur.notes || "")}}</textarea>
      </label>
      <div style="display:flex;justify-content:space-between;gap:8px;margin-top:8px">
        <button onclick="resetEntityTag('${{group}}', '${{esc(normKey)}}')" style="border-color:rgba(239,68,68,0.45);color:#f87171">🔄 Restaurar predeterminado</button>
        <div style="display:flex;gap:8px">
          <button onclick="closeModal()">Cancelar</button>
          <button class="btn-primary" onclick="saveEntityTag('${{group}}', '${{esc(normKey)}}')">Guardar Etiqueta</button>
        </div>
      </div>
    </div>
  `;
  showModal(html);
}}

function resetEntityTag(group, key) {{
  delete TAGS[group][key];
  saveTags();
  closeModal();
}}

function saveEntityTag(group, key) {{
  const label = document.getElementById("tag-label").value.trim();
  const category = document.getElementById("tag-cat").value;
  const notes = document.getElementById("tag-notes").value.trim();
  if (!label && !notes) {{
    delete TAGS[group][key];
  }} else {{
    TAGS[group][key] = {{ label, category, notes }};
  }}
  saveTags();
  closeModal();
}}

let pendingBulkKeys = [];
let pendingBulkGroup = "devices";

function openBulkTagModal(group, keys, titleText) {{
  if (!keys || keys.length === 0) return;
  pendingBulkGroup = group;
  pendingBulkKeys = keys;
  const html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge">ETIQUETADO EN LOTE (BULK TAGGING)</div>
        <h3 style="margin:6px 0 0 0">${{esc(titleText)}} (${{keys.length}} elementos)</h3>
      </div>
      <button onclick="closeModal()">✕</button>
    </div>
    <div style="display:grid;gap:12px">
      <label>Alias común / Prefijo de etiqueta (ej. "Línea Base Casa", "Oficina", "Visitante"):<br>
        <input type="text" id="bulk-tag-label" value="Línea Base" style="width:100%;margin-top:4px">
      </label>
      <label>Categoría para todos los elementos seleccionados:<br>
        <select id="bulk-tag-cat" style="width:100%;margin-top:4px">
          <option value="CONOCIDO" selected>CONOCIDO</option>
          <option value="PROPIO">PROPIO</option>
          <option value="OBJETIVO">OBJETIVO</option>
          <option value="SOSPECHOSO">SOSPECHOSO</option>
          <option value="IGNORAR">IGNORAR</option>
        </select>
      </label>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:8px">
        <button onclick="closeModal()">Cancelar</button>
        <button class="btn-primary" onclick="applyBulkTag()">Aplicar a ${{keys.length}} elementos</button>
      </div>
    </div>
  `;
  showModal(html);
}}

function applyBulkTag() {{
  const label = document.getElementById("bulk-tag-label").value.trim();
  const category = document.getElementById("bulk-tag-cat").value;
  if (!label) return;
  pendingBulkKeys.forEach(k => {{
    TAGS[pendingBulkGroup][k.toUpperCase()] = {{ label, category, notes: "Bulk tagged" }};
  }});
  saveTags();
  closeModal();
}}

function bulkTagCurrentNetworks() {{
  openBulkTagModal("networks", lastFilteredNetworks.map(a => a.bssid), "Redes filtradas actualmente");
}}

function bulkTagCurrentDevices() {{
  openBulkTagModal("devices", lastFilteredDevices.map(d => d.sta_mac), "Dispositivos filtrados actualmente");
}}

function bulkTagSetResults() {{
  const res = computeSetAlgebraResults();
  if (setAlgState.entity === "devices") {{
    openBulkTagModal("devices", res.map(d => d.sta_mac), "Dispositivos del resultado de conjuntos");
  }} else if (setAlgState.entity === "aps") {{
    openBulkTagModal("networks", res.map(a => a.bssid), "Redes del resultado de conjuntos");
  }}
}}

function openSessionEditor(sid) {{
  const sObj = DATA.sessions.find(x => x.session_id === sid) || {{}};
  const cur = getSessionTag(sid);
  const gps = cur.gps || sObj.gps || {{}};

  const html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge">CONFIGURAR SESIÓN &amp; GPS</div>
        <h3 class="mono" style="margin:6px 0 0 0">Sesión ${{esc(sid)}}</h3>
      </div>
      <button onclick="closeModal()">✕</button>
    </div>
    <div style="display:grid;gap:12px">
      <label>Nombre descriptivo de la sesión (ej. "Oficina Planta 1", "Calle Mayor"):<br>
        <input type="text" id="ses-name" value="${{esc(cur.name || "")}}" style="width:100%;margin-top:4px">
      </label>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <label>Latitud GPS de la sesión:<br>
          <input type="number" step="any" id="ses-lat" value="${{gps.lat !== undefined && gps.lat !== null ? gps.lat : ""}}" placeholder="ej. 40.416775" style="width:100%;margin-top:4px">
        </label>
        <label>Longitud GPS de la sesión:<br>
          <input type="number" step="any" id="ses-lon" value="${{gps.lon !== undefined && gps.lon !== null ? gps.lon : ""}}" placeholder="ej. -3.703790" style="width:100%;margin-top:4px">
        </label>
      </div>
      <label>Notas de la sesión:<br>
        <textarea id="ses-notes" rows="2" style="width:100%;margin-top:4px">${{esc(cur.notes || "")}}</textarea>
      </label>
      <div style="display:flex;justify-content:space-between;gap:8px;margin-top:8px">
        <button onclick="resetSessionMeta('${{esc(sid)}}')" style="border-color:rgba(239,68,68,0.45);color:#f87171">🔄 Restaurar predeterminado</button>
        <div style="display:flex;gap:8px">
          <button onclick="closeModal()">Cancelar</button>
          <button class="btn-primary" onclick="saveSessionMeta('${{esc(sid)}}')">Guardar Sesión</button>
        </div>
      </div>
    </div>
  `;
  showModal(html);
}}

function resetSessionMeta(sid) {{
  delete TAGS.sessions[sid];
  saveTags();
  closeModal();
}}

function saveSessionMeta(sid) {{
  const name = document.getElementById("ses-name").value.trim();
  const latRaw = document.getElementById("ses-lat").value.trim();
  const lonRaw = document.getElementById("ses-lon").value.trim();
  const notes = document.getElementById("ses-notes").value.trim();
  if (!name && !notes && latRaw === "" && lonRaw === "") {{
    delete TAGS.sessions[sid];
    saveTags();
    closeModal();
    return;
  }}
  const entry = TAGS.sessions[sid] || {{}};
  entry.name = name;
  entry.notes = notes;
  if (latRaw !== "" && lonRaw !== "") {{
    entry.gps = {{ lat: parseFloat(latRaw), lon: parseFloat(lonRaw), src: "manual" }};
  }} else {{
    delete entry.gps;
  }}
  TAGS.sessions[sid] = entry;
  saveTags();
  closeModal();
}}

function openTagManagerModal() {{
  const sessionOpts = DATA.sessions.map(s =>
    `<option value="${{esc(s.session_id)}}">${{esc(getSessionDisplay(s.session_id))}} (${{esc(s.first_seen)}})</option>`
  ).join("");

  const html = `
    <div class="modal-header">
      <div>
        <div class="brand-badge">NUEVA ETIQUETA / ALIAS</div>
        <h3 style="margin:6px 0 0 0">Nombrar Sesión, Dispositivo (MAC) o Red (BSSID / SSID)</h3>
      </div>
      <button onclick="closeModal()">✕</button>
    </div>
    <div style="display:grid;gap:12px">
      <label>Tipo de Entidad:<br>
        <select id="new-tag-group" style="width:100%;margin-top:4px" onchange="toggleTagModalFields()">
          <option value="sessions">Sesión de Captura (Session ID + GPS opcional)</option>
          <option value="devices">Dispositivo Cliente (STA MAC)</option>
          <option value="networks">Punto de Acceso / Red (BSSID o SSID:Nombre)</option>
        </select>
      </label>

      <div id="new-tag-session-wrap">
        <label>Seleccionar Sesión capturada (o escribir ID debajo):<br>
          <select id="new-tag-session-select" style="width:100%;margin-top:4px" onchange="onModalSessionSelect()">
            <option value="">-- Seleccionar sesión existente --</option>
            ${{sessionOpts}}
          </select>
        </label>
      </div>

      <label id="new-tag-key-label">Identificador (Session ID / MAC / BSSID / SSID:Nombre):<br>
        <input type="text" id="new-tag-key" placeholder="Ej. 029feefe, AA:BB:CC:DD:EE:FF o SSID:MiRed" style="width:100%;margin-top:4px">
      </label>

      <label>Nombre personalizado / Alias:<br>
        <input type="text" id="new-tag-label" placeholder="Ej. Auditoría Planta 1 / Móvil de Juan / Router Casa" style="width:100%;margin-top:4px">
      </label>

      <div id="new-tag-cat-wrap" style="display:none">
        <label>Categoría:<br>
          <select id="new-tag-cat" style="width:100%;margin-top:4px">
            <option value="PROPIO">PROPIO</option>
            <option value="CONOCIDO">CONOCIDO</option>
            <option value="OBJETIVO">OBJETIVO</option>
            <option value="SOSPECHOSO">SOSPECHOSO</option>
            <option value="IGNORAR">IGNORAR</option>
          </select>
        </label>
      </div>

      <div id="new-tag-gps-wrap" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <label>Latitud GPS de la sesión (opcional):<br>
          <input type="number" step="any" id="new-tag-lat" placeholder="ej. 40.416775" style="width:100%;margin-top:4px">
        </label>
        <label>Longitud GPS de la sesión (opcional):<br>
          <input type="number" step="any" id="new-tag-lon" placeholder="ej. -3.703790" style="width:100%;margin-top:4px">
        </label>
      </div>

      <label>Notas:<br>
        <textarea id="new-tag-notes" rows="2" style="width:100%;margin-top:4px" placeholder="Notas opcionales..."></textarea>
      </label>

      <div style="display:flex;justify-content:space-between;gap:8px">
        <button onclick="resetManualTag()" style="border-color:rgba(239,68,68,0.45);color:#f87171">🔄 Restaurar predeterminado</button>
        <div style="display:flex;gap:8px">
          <button onclick="closeModal()">Cancelar</button>
          <button class="btn-primary" onclick="saveManualNewTag()">Guardar</button>
        </div>
      </div>
    </div>
  `;
  showModal(html);
  if (DATA.sessions.length > 0) {{
    document.getElementById("new-tag-session-select").value = DATA.sessions[DATA.sessions.length - 1].session_id;
    onModalSessionSelect();
  }}
}}

function resetManualTag() {{
  const grp = document.getElementById("new-tag-group").value;
  let key = document.getElementById("new-tag-key").value.trim();
  if (!key) return;
  if (grp !== "sessions" && !key.startsWith("SSID:")) key = key.toUpperCase();
  delete TAGS[grp][key];
  saveTags();
  closeModal();
}}

function toggleTagModalFields() {{
  const grp = document.getElementById("new-tag-group").value;
  const isSes = (grp === "sessions");
  document.getElementById("new-tag-session-wrap").style.display = isSes ? "block" : "none";
  document.getElementById("new-tag-gps-wrap").style.display = isSes ? "grid" : "none";
  document.getElementById("new-tag-cat-wrap").style.display = isSes ? "none" : "block";
  if (!isSes) {{
    document.getElementById("new-tag-key").value = "";
    document.getElementById("new-tag-label").value = "";
    document.getElementById("new-tag-notes").value = "";
  }} else if (DATA.sessions.length > 0) {{
    onModalSessionSelect();
  }}
}}

function onModalSessionSelect() {{
  const sid = document.getElementById("new-tag-session-select").value;
  if (!sid) return;
  document.getElementById("new-tag-key").value = sid;
  const cur = getSessionTag(sid);
  const sObj = DATA.sessions.find(x => x.session_id === sid) || {{}};
  const gps = cur.gps || sObj.gps || {{}};
  document.getElementById("new-tag-label").value = cur.name || "";
  document.getElementById("new-tag-notes").value = cur.notes || "";
  document.getElementById("new-tag-lat").value = (gps.lat !== undefined && gps.lat !== null) ? gps.lat : "";
  document.getElementById("new-tag-lon").value = (gps.lon !== undefined && gps.lon !== null) ? gps.lon : "";
}}

function saveManualNewTag() {{
  const grp = document.getElementById("new-tag-group").value;
  let key = document.getElementById("new-tag-key").value.trim();
  const label = document.getElementById("new-tag-label").value.trim();
  const notes = document.getElementById("new-tag-notes").value.trim();
  if (!key) return;

  if (grp === "sessions") {{
    const latRaw = document.getElementById("new-tag-lat").value.trim();
    const lonRaw = document.getElementById("new-tag-lon").value.trim();
    if (!label && !notes && latRaw === "" && lonRaw === "") {{
      delete TAGS.sessions[key];
      saveTags();
      closeModal();
      return;
    }}
    const entry = TAGS.sessions[key] || {{}};
    entry.name = label;
    entry.notes = notes;
    if (latRaw !== "" && lonRaw !== "") {{
      entry.gps = {{ lat: parseFloat(latRaw), lon: parseFloat(lonRaw), src: "manual" }};
    }} else {{
      delete entry.gps;
    }}
    TAGS.sessions[key] = entry;
  }} else {{
    if (!key.startsWith("SSID:")) key = key.toUpperCase();
    if (!label && !notes) {{
      delete TAGS[grp][key];
    }} else {{
      const category = document.getElementById("new-tag-cat").value;
      TAGS[grp][key] = {{ label, category, notes }};
    }}
  }}
  saveTags();
  closeModal();
}}

function exportTagsJson() {{
  const blob = new Blob([JSON.stringify(TAGS, null, 2) + "\\n"], {{ type: "application/json" }});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "tags.json";
  a.click();
}}

function importTagsJson(ev) {{
  const file = ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {{
    try {{
      const obj = JSON.parse(reader.result);
      Object.assign(TAGS.sessions, obj.sessions || {{}});
      Object.assign(TAGS.networks, obj.networks || {{}});
      Object.assign(TAGS.devices, obj.devices || {{}});
      saveTags();
    }} catch (e) {{
      alert("Archivo JSON inválido");
    }}
  }};
  reader.readAsText(file);
}}

function showModal(innerHtml) {{
  document.getElementById("modal-body").innerHTML = innerHtml;
  document.getElementById("modal-backdrop").classList.add("open");
}}

function closeModal() {{
  document.getElementById("modal-backdrop").classList.remove("open");
}}

function renderAll() {{
  renderOverview();
  renderSessionsTable();
  renderNetworksTable();
  renderDevicesTable();
  renderCrossSession();
  renderTagsRegistry();
}}

renderAll();
if (window.location.protocol.startsWith("http")) {{
  const upBtn = document.getElementById("srv-upload-btn");
  if (upBtn) upBtn.style.display = "inline-flex";
  const hcBtn = document.getElementById("hc22000-dl-btn");
  if (hcBtn && (DATA.hc22000_lines || []).length > 0) hcBtn.style.display = "inline-flex";
  fetch("/api/tags").then(r => r.ok ? r.json() : null).then(srvTags => {{
    if (srvTags && (srvTags.sessions || srvTags.networks || srvTags.devices)) {{
      TAGS = {{
        sessions: Object.assign({{}}, TAGS.sessions, srvTags.sessions || {{}}),
        networks: Object.assign({{}}, TAGS.networks, srvTags.networks || {{}}),
        devices: Object.assign({{}}, TAGS.devices, srvTags.devices || {{}})
      }};
      renderAll();
    }}
  }}).catch(() => {{}});
}}
</script>
</body>
</html>
"""
    html_path.write_text(doc, encoding="utf-8")
