#!/usr/bin/env python3
"""
mem_timeline_report.py — Script compagnon pour le plugin Volatility mem_timeline.

Lit la sortie JSON produite par :
    python vol.py -f dump.raw windows.mem_timeline --json-output timeline.json

Génère un rapport HTML de timeline forensique autonome et interactif.

Utilisation :
    python mem_timeline_report.py timeline.json
    python mem_timeline_report.py timeline.json --output report.html
    python mem_timeline_report.py timeline.json --title "Incident 2026-06-15"
"""

# --- Imports standards (aucune dépendance externe : le script reste portable) ---
import argparse   # parsing des arguments de la ligne de commande (interface CLI propre)
import json       # lecture du JSON produit par Volatility + sérialisation pour l'injecter dans le JS
import sys        # accès à stderr et sys.exit() pour gérer proprement les erreurs fatales
from pathlib import Path  # manipulation orientée-objet des chemins (plus robuste que os.path)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>__REPORT_TITLE__</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d1117;--surf:#161b22;--bord:#21262d;--bord2:#30363d;
    --text:#e6edf3;--muted:#8b949e;--acc:#58a6ff;
    --pc:#58a6ff;--pe:#f85149;--tc:#3fb950;--dl:#d29922;--ot:#a5a5a5;
    --mono:'JetBrains Mono','Fira Mono','Cascadia Code','Consolas',monospace;
    --ui:'Inter','Segoe UI',system-ui,sans-serif;
  }
  html,body{height:100%}
  body{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:13px;line-height:1.5;display:flex;flex-direction:column}

  #topbar{position:sticky;top:0;z-index:100;background:var(--surf);border-bottom:1px solid var(--bord2);padding:10px 18px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  #topbar h1{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--acc);letter-spacing:.04em;flex-shrink:0}
  .chip{font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:4px;border:1px solid var(--bord2);color:var(--muted);white-space:nowrap}
  .chip span{color:var(--text);font-weight:600}
  #tb-title{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}

  #controls{background:var(--surf);border-bottom:1px solid var(--bord);padding:8px 18px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .cl{font-size:11px;color:var(--muted);white-space:nowrap}
  input[type=text],select{background:var(--bg);border:1px solid var(--bord2);color:var(--text);font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:5px;outline:none;transition:border-color .15s}
  input[type=text]:focus,select:focus{border-color:var(--acc)}
  #srch{width:200px}
  .pills{display:flex;gap:5px;flex-wrap:wrap}
  .pill{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:999px;border:1px solid transparent;cursor:pointer;opacity:.4;transition:opacity .15s;user-select:none}
  .pill.on{opacity:1;border-color:currentColor}
  .pill[data-cat=PROCESS_CREATE]{color:var(--pc);background:#0d2240}
  .pill[data-cat=PROCESS_EXIT]{color:var(--pe);background:#2d1010}
  .pill[data-cat=THREAD_CREATE]{color:var(--tc);background:#0d2a14}
  .pill[data-cat=DLL_LOAD]{color:var(--dl);background:#2a1e04}
  .pill[data-cat=OTHER]{color:var(--ot);background:#1e1e1e}
  .btn{background:var(--bord2);border:1px solid var(--bord2);color:var(--text);font-size:11px;padding:4px 10px;border-radius:5px;cursor:pointer;transition:background .15s}
  .btn:hover{background:#2d333b}

  #main{flex:1;overflow-y:auto;padding:12px 18px 40px}
  .pg{margin-bottom:8px;border:1px solid var(--bord);border-radius:7px;overflow:hidden;transition:border-color .15s}
  .pg:hover{border-color:var(--bord2)}
  .ph{display:flex;align-items:center;gap:8px;padding:8px 14px;background:var(--surf);cursor:pointer;user-select:none;border-bottom:1px solid transparent;transition:background .12s}
  .pg.open .ph{border-bottom-color:var(--bord)}
  .ph:hover{background:#1c2130}
  .chev{font-size:9px;color:var(--muted);transition:transform .2s;flex-shrink:0}
  .pg.open .chev{transform:rotate(90deg)}
  .pname{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--text)}
  .ppid{font-family:var(--mono);font-size:10px;color:var(--muted);background:var(--bord);padding:1px 6px;border-radius:4px}
  .psumm{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
  .pcnt{font-family:var(--mono);font-size:10px;padding:1px 7px;border-radius:4px}
  .pcnt[data-cat=PROCESS_CREATE]{background:#0d2240;color:var(--pc)}
  .pcnt[data-cat=PROCESS_EXIT]{background:#2d1010;color:var(--pe)}
  .pcnt[data-cat=THREAD_CREATE]{background:#0d2a14;color:var(--tc)}
  .pcnt[data-cat=DLL_LOAD]{background:#2a1e04;color:var(--dl)}
  .pb{display:none}
  .pg.open .pb{display:block}
  .evhdr{display:grid;grid-template-columns:200px 145px 1fr 260px;padding:4px 14px 4px 28px;background:#0d1117;border-bottom:1px solid var(--bord2);font-size:10px;font-family:var(--mono);color:var(--muted);letter-spacing:.06em;text-transform:uppercase}
  .evrow{display:grid;grid-template-columns:200px 145px 1fr 260px;padding:6px 14px 6px 28px;border-bottom:1px solid var(--bord);align-items:baseline;transition:background .1s}
  .evrow:last-child{border-bottom:none}
  .evrow:hover{background:#161b22cc}
  .evts{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}
  .evcat{font-family:var(--mono);font-size:10px;font-weight:700;white-space:nowrap}
  .evcat[data-cat=PROCESS_CREATE]{color:var(--pc)}
  .evcat[data-cat=PROCESS_EXIT]{color:var(--pe)}
  .evcat[data-cat=THREAD_CREATE]{color:var(--tc)}
  .evcat[data-cat=DLL_LOAD]{color:var(--dl)}
  .evcat[data-cat=OTHER]{color:var(--ot)}
  .evdesc{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:8px}
  .evextra{font-family:var(--mono);font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #empty{display:none;text-align:center;padding:60px;color:var(--muted);font-family:var(--mono);font-size:13px}
  ::-webkit-scrollbar{width:5px;height:5px}
  ::-webkit-scrollbar-thumb{background:var(--bord2);border-radius:3px}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
</head>
<body>

<div id="topbar">
  <h1>&#x2B21; MEM TIMELINE</h1>
  <div class="chip">Events: <span id="sv">0</span> / <span id="st">0</span></div>
  <div class="chip">Processes: <span id="sp">0</span></div>
  <div class="chip">Range: <span id="sr">&#8212;</span></div>
  <div id="tb-title">__REPORT_TITLE__</div>
</div>

<div id="controls">
  <span class="cl">Search</span>
  <input type="text" id="srch" placeholder="process, DLL, description, PID..." />
  <span class="cl">PID</span>
  <select id="pf"><option value="">All PIDs</option></select>
  <div class="pills" id="pills"></div>
  <div style="margin-left:auto;display:flex;gap:6px">
    <button class="btn" id="bexp">Expand All</button>
    <button class="btn" id="bcol">Collapse All</button>
    <button class="btn" id="brst">Reset</button>
  </div>
</div>

<div id="main">
  <div id="gc"></div>
  <div id="empty">No events match the current filters.</div>
</div>

<script>
const EVENTS = __EVENTS_JSON__;

const CAT_LABELS = {
  PROCESS_CREATE: 'PROCESS_CREATE',
  PROCESS_EXIT:   'PROCESS_EXIT',
  THREAD_CREATE:  'THREAD_CREATE',
  DLL_LOAD:       'DLL_LOAD'
};

let activeCats = new Set();
let allCats = new Set();
let pidFilter = '';
let srchFilter = '';

function h(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function parseTs(ts) {
  if (!ts || ts === 'N/A') return null;
  try { return new Date(ts.replace(' ','T') + 'Z'); } catch(e) { return null; }
}

function extraText(ev) {
  const skip = new Set(['timestamp','category','pid','process','description']);
  return Object.entries(ev).filter(([k]) => !skip.has(k)).map(([k,v]) => k+'='+v).join('  ');
}

function filteredEvents() {
  return EVENTS.filter(ev => {
    const cat = ev.category || 'OTHER';
    if (!activeCats.has(cat)) return false;
    if (pidFilter && String(ev.pid) !== pidFilter) return false;
    if (srchFilter) {
      const hay = [ev.process, ev.description, String(ev.pid),
        ev.dll_name, ev.dll_path, ev.offset].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(srchFilter)) return false;
    }
    return true;
  });
}

function render() {
  const vis = filteredEvents();
  document.getElementById('sv').textContent = vis.length;

  const groups = new Map();
  vis.forEach(ev => {
    const key = ev.process + ':' + ev.pid;
    if (!groups.has(key)) groups.set(key, { name: ev.process, pid: ev.pid, events: [] });
    groups.get(key).events.push(ev);
  });

  document.getElementById('sp').textContent = groups.size;

  const openKeys = new Set([...document.querySelectorAll('.pg.open')].map(el => el.dataset.k));
  const gc = document.getElementById('gc');
  gc.innerHTML = '';
  document.getElementById('empty').style.display = groups.size === 0 ? 'block' : 'none';

  groups.forEach((grp, key) => {
    const isOpen = openKeys.size === 0 || openKeys.has(key);
    const counts = {};
    grp.events.forEach(ev => {
      const c = ev.category || 'OTHER';
      counts[c] = (counts[c] || 0) + 1;
    });

    const el = document.createElement('div');
    el.className = 'pg' + (isOpen ? ' open' : '');
    el.dataset.k = key;

    const chips = Object.entries(counts)
      .map(([c,n]) => '<span class="pcnt" data-cat="'+c+'">'+c.replace('_',' ')+' '+n+'</span>')
      .join('');

    const rows = grp.events.map(ev => {
      const cat = ev.category || 'OTHER';
      const extra = extraText(ev);
      return '<div class="evrow">'
        + '<span class="evts">'+h(ev.timestamp)+'</span>'
        + '<span class="evcat" data-cat="'+cat+'">'+cat+'</span>'
        + '<span class="evdesc" title="'+h(ev.description)+'">'+h(ev.description)+'</span>'
        + '<span class="evextra" title="'+h(extra)+'">'+h(extra)+'</span>'
        + '</div>';
    }).join('');

    el.innerHTML = '<div class="ph">'
      + '<span class="chev">&#9658;</span>'
      + '<span class="pname">'+h(grp.name)+'</span>'
      + '<span class="ppid">PID '+grp.pid+'</span>'
      + '<div class="psumm">'+chips+'</div>'
      + '</div>'
      + '<div class="pb">'
      + '<div class="evhdr"><span>Timestamp</span><span>Category</span><span>Description</span><span>Details</span></div>'
      + rows
      + '</div>';

    el.querySelector('.ph').addEventListener('click', () => el.classList.toggle('open'));
    gc.appendChild(el);
  });
}

function buildUI() {
  const pids = new Set();
  EVENTS.forEach(ev => {
    const cat = ev.category || 'OTHER';
    allCats.add(cat);
    activeCats.add(cat);
    pids.add(ev.pid);
  });

  // Pills
  const pillsEl = document.getElementById('pills');
  [...allCats].sort().forEach(cat => {
    const p = document.createElement('span');
    p.className = 'pill on';
    p.dataset.cat = cat;
    p.textContent = cat;
    p.addEventListener('click', () => {
      if (activeCats.has(cat)) activeCats.delete(cat);
      else activeCats.add(cat);
      p.classList.toggle('on', activeCats.has(cat));
      render();
    });
    pillsEl.appendChild(p);
  });

  // PID select
  const pf = document.getElementById('pf');
  [...pids].sort((a,b) => Number(a)-Number(b)).forEach(pid => {
    const o = document.createElement('option');
    o.value = pid; o.textContent = 'PID ' + pid;
    pf.appendChild(o);
  });

  // Time range display
  const dates = EVENTS.map(ev => parseTs(ev.timestamp)).filter(Boolean);
  if (dates.length) {
    const mn = new Date(Math.min(...dates.map(d => d.getTime())));
    const mx = new Date(Math.max(...dates.map(d => d.getTime())));
    document.getElementById('sr').textContent =
      mn.toISOString().slice(0,19).replace('T',' ') + ' \u2192 ' +
      mx.toISOString().slice(0,19).replace('T',' ');
  }

  document.getElementById('st').textContent = EVENTS.length;

  document.getElementById('srch').addEventListener('input', e => {
    srchFilter = e.target.value.toLowerCase(); render();
  });
  document.getElementById('pf').addEventListener('change', e => {
    pidFilter = e.target.value; render();
  });
  document.getElementById('bexp').addEventListener('click', () => {
    document.querySelectorAll('.pg').forEach(g => g.classList.add('open'));
  });
  document.getElementById('bcol').addEventListener('click', () => {
    document.querySelectorAll('.pg').forEach(g => g.classList.remove('open'));
  });
  document.getElementById('brst').addEventListener('click', () => {
    srchFilter = ''; pidFilter = '';
    document.getElementById('srch').value = '';
    document.getElementById('pf').value = '';
    allCats.forEach(c => activeCats.add(c));
    document.querySelectorAll('.pill').forEach(p => p.classList.add('on'));
    render();
  });

  render();
}

buildUI();
</script>
</body>
</html>"""


def generate_report(json_path: str, output_path: str, title: str) -> None:
    """
    Construit le rapport HTML autonome à partir du JSON de timeline.

    Principe : on lit le JSON produit par le plugin Volatility, puis on
    fait un simple remplacement de chaînes (str.replace) dans le template
    HTML pour injecter les données et le titre. Pas de moteur de templating.
    """

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("timeline", [])
    if not events:
        print(f"[!] No events found in {json_path}", file=sys.stderr)
        print(f"    Make sure the JSON has a top-level 'timeline' key.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loaded {len(events)} events from {json_path}")

    events_json = json.dumps(events, ensure_ascii=False)

    safe_title = title.replace("<", "&lt;").replace(">", "&gt;")

    html = HTML_TEMPLATE.replace("__EVENTS_JSON__", events_json).replace("__REPORT_TITLE__", safe_title)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report written to: {output_path}")
    print(f"    Open in any browser — fully standalone.")


def main() -> None:
    """
    Point d'entrée CLI. Utilise argparse pour définir une interface en ligne
    de commande propre : un argument positionnel obligatoire, deux options
    facultatives, et une aide auto-générée (--help / -h).
    """
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML memory timeline report from Volatility JSON output."
    )
    parser.add_argument("json_file", help="Path to timeline.json produced by mem_timeline plugin")

    # Argument optionnel avec forme courte (-o) et longue (--output).
    # default=None (et non une chaîne vide) est volontaire : ça permet plus
    # bas de distinguer "non fourni" de "fourni mais vide" via l'opérateur `or`.
    parser.add_argument("--output", "-o", default=None,
        help="Output HTML path (default: <stem>_report.html)")

    # Argument optionnel avec valeur par défaut explicite (pas besoin de
    # logique conditionnelle ensuite, argparse s'en charge directement).
    parser.add_argument("--title", "-t", default="Memory Activity Timeline",
        help="Report title (default: 'Memory Activity Timeline')")

    args = parser.parse_args()  # parse sys.argv ; lève SystemExit si arguments invalides


    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"[!] File not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or str(json_path.with_name(json_path.stem + "_report.html"))


    generate_report(str(json_path), output_path, args.title)


if __name__ == "__main__":
    main()