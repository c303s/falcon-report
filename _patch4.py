"""Round-4 patch: eye icons, UNASSN, sub-line ages, house left, section renames, initial collapse.

Execution order within Python-template section matters:
  stat-grid MERGES must run BEFORE UNASSN label replacements, because merges
  use the original "Unassigned" text as the old pattern and emit "Unassn" in
  the replacement; running UNASSN first would rename the text and make the
  merge pattern fail.
"""
import re, sys

EYE_OPEN = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" '
    'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>'
    '<circle cx="12" cy="12" r="3"/></svg>'
)
EYE_CLOSED = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" '
    'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round">'
    '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94'
    'M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19'
    'm-6.72-1.07a3 3 0 1 1-4.24-4.24"/>'
    '<line x1="1" y1="1" x2="23" y2="23"/></svg>'
)

def sub1(c, old, new, label):
    if old not in c:
        print(f"  SKIP: {label}")
        return c
    print(f"  OK: {label}")
    return c.replace(old, new, 1)

def repsub(c, pat, repl, label, flags=re.DOTALL, count=1):
    result, n = re.subn(pat, repl, c, count=count, flags=flags)
    if n == 0:
        print(f"  SKIP (no match): {label}")
        return c
    print(f"  OK ({n}x): {label}")
    return result

# ════════════════════════════════════════════════════════════════════════════
print("\n=== Patching current.html ===")
with open("current.html", encoding="utf-8") as f:
    html = f.read()

# ── CSS ──────────────────────────────────────────────────────────────────────
html = sub1(html,
    "        .toggle-btn { font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; color: var(--muted); background: none; border: none; cursor: pointer; padding: 0; }",
    "        .toggle-btn { line-height: 0; color: var(--muted); background: none; border: none; cursor: pointer; padding: 0; vertical-align: middle; opacity: 0.65; }\n"
    "        .toggle-btn:hover { opacity: 1; }",
    "toggle-btn CSS")

html = sub1(html,
    "        .section-divider .collapse-indicator { font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; text-transform: none; color: var(--muted); }",
    "        .section-divider .collapse-indicator { line-height: 0; color: var(--muted); opacity: 0.65; margin-left: 8px; }\n"
    "        .section-divider .collapse-indicator:hover { opacity: 1; }\n"
    "        .stat-value-sub { font-size: 0.76rem; color: var(--muted); margin-top: 5px; font-weight: 400; line-height: 1.5; }",
    "collapse-indicator + stat-value-sub CSS")

html = sub1(html,
    "        .back-to-top { color: var(--muted); text-decoration: none; margin-left: 14px; font-size: 1.1rem; opacity: 0.55; transition: opacity 0.15s, color 0.15s; }",
    "        .back-to-top { color: var(--muted); text-decoration: none; margin-right: 10px; font-size: 1.1rem; opacity: 0.55; transition: opacity 0.15s, color 0.15s; }",
    "back-to-top margin direction")

# ── Move house icon before each section title ────────────────────────────────
for title in ['General Overview', 'Detections', 'Automated Leads', 'Activity']:
    html = sub1(html,
        f'{title} <a class="back-to-top" href="#top" title="Back to top">&#8962;</a></h2>',
        f'<a class="back-to-top" href="#top" title="Back to top">&#8962;</a> {title}</h2>',
        f"house before {title}")

# Cases: rename + move house
html = sub1(html,
    'New and Unassigned Cases <a class="back-to-top" href="#top" title="Back to top">&#8962;</a></h2>',
    '<a class="back-to-top" href="#top" title="Back to top">&#8962;</a> Cases</h2>',
    "house before Cases + rename")

# ── Cases data-section ───────────────────────────────────────────────────────
html = sub1(html, 'data-section="new and unassigned cases"', 'data-section="cases"', "Cases data-section")

# ── Cases panel: restore panel-h2-row with h2 title + eye toggle ────────────
html = sub1(html,
    '<div style="text-align:right;margin-bottom:8px">'
    '<button class="toggle-btn" id="cases-overview-toggle">Hide</button></div>',
    f'<div class="panel-h2-row"><h2>New and Unassigned Cases</h2>'
    f'<button class="toggle-btn" id="cases-overview-toggle" title="Toggle">{EYE_CLOSED}</button></div>',
    "Cases panel h2 + eye toggle")

# ── Det overview toggle: text → eye SVG ─────────────────────────────────────
html = sub1(html,
    '<div class="panel-h2-row"><h2>New and Unassigned Detections</h2>'
    '<button class="toggle-btn" id="det-overview-toggle">Hide</button></div>',
    f'<div class="panel-h2-row"><h2>New and Unassigned Detections</h2>'
    f'<button class="toggle-btn" id="det-overview-toggle" title="Toggle">{EYE_CLOSED}</button></div>',
    "Det toggle eye SVG")

# ── UNASSIGNED → UNASSN in stat-labels ──────────────────────────────────────
for old_text, new_text in [
    ('Unassigned detections',     'Unassn Detections'),
    ('Unassigned cases',          'Unassn Cases'),
    ('Unassigned leads',          'Unassn Leads'),
    ('Avg unassigned age (365d)', 'Avg Unassn Age (365d)'),
    ('Newest unassigned (365d)',  'Newest Unassn (365d)'),
    ('Oldest unassigned (365d)',  'Oldest Unassn (365d)'),
    ('Avg unassigned age',        'Avg Unassn Age'),
    ('Newest unassigned',         'Newest Unassn'),
    ('Oldest unassigned',         'Oldest Unassn'),
]:
    old_full = f'<div class="stat-label">{old_text}</div>'
    new_full = f'<div class="stat-label">{new_text}</div>'
    n = html.count(old_full)
    if n == 0:
        print(f"  SKIP: stat-label: {old_text}")
    else:
        html = html.replace(old_full, new_full)  # replace ALL occurrences
        print(f"  OK: stat-label: {old_text}")


# Table header in det-unassigned-table
html = sub1(html,
    '<th>Category</th><th>Unassigned</th>\n                            <th>Newest</th><th>Oldest</th>',
    '<th>Category</th><th>Unassn</th>\n                            <th>Newest</th><th>Oldest</th>',
    "table header Unassigned→Unassn")

# ── Det stat-grid: merge age boxes into sub-line ─────────────────────────────
m_det_avg     = re.search(r'<div class="stat"><div class="stat-label">Avg Unassn Age \(365d\)</div>'
                           r'<div class="stat-value">(.*?)</div></div>', html, re.DOTALL)
m_det_newest  = re.search(r'<div class="stat"><div class="stat-label">Newest Unassn \(365d\)</div>'
                           r'<div class="stat-value" id="det-unassigned-newest">(.*?)</div></div>', html, re.DOTALL)
m_det_oldest  = re.search(r'<div class="stat"><div class="stat-label">Oldest Unassn \(365d\)</div>'
                           r'<div class="stat-value" id="det-unassigned-oldest">(.*?)</div></div>', html, re.DOTALL)
if m_det_avg and m_det_newest and m_det_oldest:
    det_sub = (
        f'<div class="stat-value-sub">'
        f'Avg <span id="det-unassigned-avg">{m_det_avg.group(1)}</span> &middot; '
        f'Newest <span id="det-unassigned-newest">{m_det_newest.group(1)}</span> &middot; '
        f'Oldest <span id="det-unassigned-oldest">{m_det_oldest.group(1)}</span>'
        f'</div>'
    )
    html = repsub(html,
        r'(<div class="stat"><div class="stat-label">Unassn Detections</div>'
        r'<div class="stat-value" id="det-unassigned-count">.*?</div>)(</div>)',
        r'\1' + det_sub + r'\2',
        "det: insert sub-line")
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Avg Unassn Age \(365d\)</div>'
                  r'<div class="stat-value">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Newest Unassn \(365d\)</div>'
                  r'<div class="stat-value" id="det-unassigned-newest">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Oldest Unassn \(365d\)</div>'
                  r'<div class="stat-value" id="det-unassigned-oldest">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    print("  OK: Det stat-grid merged")
else:
    print(f"  SKIP: Det stat-grid capture: avg={bool(m_det_avg)} newest={bool(m_det_newest)} oldest={bool(m_det_oldest)}")

# ── Cases stat-grid: merge age boxes into sub-line ────────────────────────────
m_cas_avg    = re.search(r'<div class="stat"><div class="stat-label">Avg Unassn Age \(365d\)</div>'
                          r'<div class="stat-value">(.*?)</div></div>', html, re.DOTALL)
m_cas_newest = re.search(r'<div class="stat"><div class="stat-label">Newest Unassn \(365d\)</div>'
                          r'<div class="stat-value" id="cases-unassigned-newest">(.*?)</div></div>', html, re.DOTALL)
m_cas_oldest = re.search(r'<div class="stat"><div class="stat-label">Oldest Unassn \(365d\)</div>'
                          r'<div class="stat-value" id="cases-unassigned-oldest">(.*?)</div></div>', html, re.DOTALL)
if m_cas_avg and m_cas_newest and m_cas_oldest:
    cas_sub = (
        f'<div class="stat-value-sub">'
        f'Avg <span id="cases-unassigned-avg">{m_cas_avg.group(1)}</span> &middot; '
        f'Newest <span id="cases-unassigned-newest">{m_cas_newest.group(1)}</span> &middot; '
        f'Oldest <span id="cases-unassigned-oldest">{m_cas_oldest.group(1)}</span>'
        f'</div>'
    )
    html = repsub(html,
        r'(<div class="stat"><div class="stat-label">Unassn Cases</div>'
        r'<div class="stat-value" id="cases-unassigned-count">.*?</div>)(</div>)',
        r'\1' + cas_sub + r'\2',
        "cases: insert sub-line")
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Avg Unassn Age \(365d\)</div>'
                  r'<div class="stat-value">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Newest Unassn \(365d\)</div>'
                  r'<div class="stat-value" id="cases-unassigned-newest">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Oldest Unassn \(365d\)</div>'
                  r'<div class="stat-value" id="cases-unassigned-oldest">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    print("  OK: Cases stat-grid merged")
else:
    print(f"  SKIP: Cases stat-grid capture: avg={bool(m_cas_avg)} newest={bool(m_cas_newest)} oldest={bool(m_cas_oldest)}")

# ── Leads stat-grid: merge age boxes into sub-line ───────────────────────────
m_lea_avg    = re.search(r'<div class="stat"><div class="stat-label">Avg Unassn Age</div>'
                          r'<div class="stat-value">(.*?)</div></div>', html, re.DOTALL)
m_lea_newest = re.search(r'<div class="stat"><div class="stat-label">Newest Unassn</div>'
                          r'<div class="stat-value">(.*?)</div></div>', html, re.DOTALL)
m_lea_oldest = re.search(r'<div class="stat"><div class="stat-label">Oldest Unassn</div>'
                          r'<div class="stat-value">(.*?)</div></div>', html, re.DOTALL)
if m_lea_avg and m_lea_newest and m_lea_oldest:
    lea_sub = (
        f'<div class="stat-value-sub">'
        f'Avg {m_lea_avg.group(1)} &middot; '
        f'Newest {m_lea_newest.group(1)} &middot; '
        f'Oldest {m_lea_oldest.group(1)}'
        f'</div>'
    )
    html = repsub(html,
        r'(<div class="stat"><div class="stat-label">Unassn Leads</div>'
        r'<div class="stat-value">.*?</div>)(</div>)',
        r'\1' + lea_sub + r'\2',
        "leads: insert sub-line")
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Avg Unassn Age</div>'
                  r'<div class="stat-value">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Newest Unassn</div>'
                  r'<div class="stat-value">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    html = re.sub(r'\s*<div class="stat"><div class="stat-label">Oldest Unassn</div>'
                  r'<div class="stat-value">.*?</div></div>', '', html, count=1, flags=re.DOTALL)
    print("  OK: Leads stat-grid merged")
else:
    print(f"  SKIP: Leads stat-grid: avg={bool(m_lea_avg)} newest={bool(m_lea_newest)} oldest={bool(m_lea_oldest)}")

# ── JS: add EYE constants + update toggle functions ──────────────────────────
html = sub1(html,
    "        function processUnassignedTableHtml(rawHtml) {",
    f"        const EYE_OPEN = `{EYE_OPEN}`;\n"
    f"        const EYE_CLOSED = `{EYE_CLOSED}`;\n\n"
    "        function processUnassignedTableHtml(rawHtml) {",
    "JS EYE constants")

html = sub1(html,
    "        function toggleDetOverview() {\n"
    "            const art = document.getElementById('det-overview-article');\n"
    "            const btn = document.getElementById('det-overview-toggle');\n"
    "            const hidden = art.style.display === 'none';\n"
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.textContent = hidden ? 'Hide' : 'Show';\n"
    "        }",
    "        function toggleDetOverview() {\n"
    "            const art = document.getElementById('det-overview-article');\n"
    "            const btn = document.getElementById('det-overview-toggle');\n"
    "            const hidden = art.style.display === 'none';\n"
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;\n"
    "        }",
    "toggleDetOverview eye")

html = sub1(html,
    "        function toggleCasesOverview() {\n"
    "            const art = document.getElementById('cases-overview-article');\n"
    "            const btn = document.getElementById('cases-overview-toggle');\n"
    "            const hidden = art.style.display === 'none';\n"
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.textContent = hidden ? 'Hide' : 'Show';\n"
    "        }",
    "        function toggleCasesOverview() {\n"
    "            const art = document.getElementById('cases-overview-article');\n"
    "            const btn = document.getElementById('cases-overview-toggle');\n"
    "            const hidden = art.style.display === 'none';\n"
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;\n"
    "        }",
    "toggleCasesOverview eye")

# ── JS renderDetections: add det-unassigned-avg + det-unassigned-title ───────
html = sub1(html,
    "            if (payload365) {\n"
    "                document.getElementById('det-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }",
    "            if (payload365) {\n"
    "                document.getElementById('det-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }",
    "renderDetections: avg sub-line update")

html = sub1(html,
    "document.getElementById('det-unassigned-title').textContent = `Unassigned Detections (${range})`;",
    "document.getElementById('det-unassigned-title').textContent = `Unassn Detections (${range})`;",
    "renderDetections: title Unassn")

# ── JS renderCases: add cases-unassigned-avg ─────────────────────────────────
html = sub1(html,
    "            if (payload365) {\n"
    "                document.getElementById('cases-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }",
    "            if (payload365) {\n"
    "                document.getElementById('cases-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }",
    "renderCases: avg sub-line update")

# ── JS initCollapsibleSections: eye icons + initial collapse ─────────────────
html = sub1(html,
    "            const collapsibleSections = new Set(['general overview', 'detections', 'new and unassigned cases', 'automated leads', 'activity']);",
    "            const collapsibleSections = new Set(['general overview', 'detections', 'cases', 'automated leads', 'activity']);\n"
    "            const initiallyCollapsed = new Set(['cases', 'automated leads', 'activity']);",
    "collapsibleSections + initiallyCollapsed")

html = sub1(html,
    "                const indicator = document.createElement('span');\n"
    "                indicator.className = 'collapse-indicator';\n"
    "                divider.appendChild(indicator);\n\n"
    "                const setExpanded = (expanded) => {\n"
    "                    divider.setAttribute('aria-expanded', expanded ? 'true' : 'false');\n"
    "                    indicator.textContent = expanded ? 'Hide' : 'Show';",
    "                const indicator = document.createElement('span');\n"
    "                indicator.className = 'collapse-indicator';\n"
    "                divider.appendChild(indicator);\n\n"
    "                const setExpanded = (expanded) => {\n"
    "                    divider.setAttribute('aria-expanded', expanded ? 'true' : 'false');\n"
    "                    indicator.innerHTML = expanded ? EYE_CLOSED : EYE_OPEN;",
    "collapse-indicator eye icons")

html = sub1(html,
    "                setExpanded(true);",
    "                setExpanded(!initiallyCollapsed.has(label));",
    "initial collapse logic")

with open("current.html", "w", encoding="utf-8") as f:
    f.write(html)
print("current.html written.\n")

# ════════════════════════════════════════════════════════════════════════════
# Python section — CRITICAL ORDER:
#   1. build_cases_payload
#   2. CSS + section dividers + panel/toggle HTML
#   3. STAT-GRID MERGES (FIRST — uses original "Unassigned" text)
#   4. UNASSN label replacements (AFTER merges — most will SKIP)
#   5. JS changes
# ════════════════════════════════════════════════════════════════════════════
print("=== Patching falcon_overview.py ===")
with open("falcon_overview.py", encoding="utf-8") as f:
    py = f.read()

# ── build_cases_payload: add avg_unassigned_age_html ─────────────────────────
py = sub1(py,
    '                "oldest_unassigned_age_html": age_value_html(oldest_unassigned_case_age),\n'
    '                "newest_unassigned_age_html": age_value_html(newest_unassigned_case_age),\n'
    '                "by_severity_html": counter_rows_html(cases_by_severity, preferred_order=SEVERITY_LABELS),',
    '                "oldest_unassigned_age_html": age_value_html(oldest_unassigned_case_age),\n'
    '                "newest_unassigned_age_html": age_value_html(newest_unassigned_case_age),\n'
    '                "avg_unassigned_age_html": age_value_html(cases_avg_age),\n'
    '                "by_severity_html": counter_rows_html(cases_by_severity, preferred_order=SEVERITY_LABELS),',
    "py build_cases_payload: avg_unassigned_age_html")

# ── CSS template ─────────────────────────────────────────────────────────────
py = sub1(py,
    "        .toggle-btn {{ font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; color: var(--muted); background: none; border: none; cursor: pointer; padding: 0; }}",
    "        .toggle-btn {{ line-height: 0; color: var(--muted); background: none; border: none; cursor: pointer; padding: 0; vertical-align: middle; opacity: 0.65; }}\n"
    "        .toggle-btn:hover {{ opacity: 1; }}",
    "py toggle-btn CSS")

py = sub1(py,
    "        .section-divider .collapse-indicator {{ font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; text-transform: none; color: var(--muted); }}",
    "        .section-divider .collapse-indicator {{ line-height: 0; color: var(--muted); opacity: 0.65; margin-left: 8px; }}\n"
    "        .section-divider .collapse-indicator:hover {{ opacity: 1; }}\n"
    "        .stat-value-sub {{ font-size: 0.76rem; color: var(--muted); margin-top: 5px; font-weight: 400; line-height: 1.5; }}",
    "py collapse-indicator + stat-value-sub CSS")

py = sub1(py,
    "        .back-to-top {{ color: var(--muted); text-decoration: none; margin-left: 14px; font-size: 1.1rem; opacity: 0.55; transition: opacity 0.15s, color 0.15s; }}",
    "        .back-to-top {{ color: var(--muted); text-decoration: none; margin-right: 10px; font-size: 1.1rem; opacity: 0.55; transition: opacity 0.15s, color 0.15s; }}",
    "py back-to-top direction")

# ── Section dividers in template: move house before title ────────────────────
for title in ['General Overview', 'Detections', 'Automated Leads', 'Activity']:
    py = sub1(py,
        f'{title} <a class=\\"back-to-top\\" href=\\"#top\\" title=\\"Back to top\\">&#8962;</a></h2>',
        f'<a class=\\"back-to-top\\" href=\\"#top\\" title=\\"Back to top\\">&#8962;</a> {title}</h2>',
        f"py house before {title}")

py = sub1(py,
    'New and Unassigned Cases <a class=\\"back-to-top\\" href=\\"#top\\" title=\\"Back to top\\">&#8962;</a></h2>',
    '<a class=\\"back-to-top\\" href=\\"#top\\" title=\\"Back to top\\">&#8962;</a> Cases</h2>',
    "py house before Cases + rename")

py = sub1(py,
    'data-section=\\"new and unassigned cases\\"',
    'data-section=\\"cases\\"',
    "py Cases data-section")

# ── Cases panel template ──────────────────────────────────────────────────────
py = sub1(py,
    '<div style=\\"text-align:right;margin-bottom:8px\\">'
    '<button class=\\"toggle-btn\\" id=\\"cases-overview-toggle\\">Hide</button></div>',
    '<div class=\\"panel-h2-row\\"><h2>New and Unassigned Cases</h2>'
    '<button class=\\"toggle-btn\\" id=\\"cases-overview-toggle\\" title=\\"Toggle\\">&#128065;</button></div>',
    "py Cases panel h2 + toggle placeholder")

# Replace placeholder eye with actual SVG
eye_closed_py = EYE_CLOSED.replace('"', '\\"')
py = sub1(py,
    '<button class=\\"toggle-btn\\" id=\\"cases-overview-toggle\\" title=\\"Toggle\\">&#128065;</button>',
    f'<button class=\\"toggle-btn\\" id=\\"cases-overview-toggle\\" title=\\"Toggle\\">{eye_closed_py}</button>',
    "py Cases panel toggle SVG")

# Det toggle button in template
py = sub1(py,
    '<div class=\\"panel-h2-row\\"><h2>New and Unassigned Detections</h2>'
    '<button class=\\"toggle-btn\\" id=\\"det-overview-toggle\\">Hide</button></div>',
    '<div class=\\"panel-h2-row\\"><h2>New and Unassigned Detections</h2>'
    f'<button class=\\"toggle-btn\\" id=\\"det-overview-toggle\\" title=\\"Toggle\\">{eye_closed_py}</button></div>',
    "py Det toggle eye SVG")

# ── Det stat-grid template: merge into sub-line (BEFORE UNASSN) ──────────────
# Uses ORIGINAL "Unassigned" text in old-pattern; new-content uses "Unassn".
py = sub1(py,
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassigned detections</div>'
    '<div class=\\"stat-value\\" id=\\"det-unassigned-count\\">'
    "{detection_initial['new_unassigned']} {_det_pct_html}"
    '</div></div>\n'
    '                <div class="stat"><div class="stat-label">Avg unassigned age (365d)</div>'
    '<div class="stat-value">{age_value_html(avg_unassigned_detection_age_365d)}</div></div>\n'
    '                <div class="stat"><div class="stat-label">Newest unassigned (365d)</div>'
    "<div class=\"stat-value\" id=\"det-unassigned-newest\">{detection_365d['newest_unassigned_age_html']}</div></div>\n"
    '                <div class="stat"><div class="stat-label">Oldest unassigned (365d)</div>'
    "<div class=\"stat-value\" id=\"det-unassigned-oldest\">{detection_365d['oldest_unassigned_age_html']}</div></div>",
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassn Detections</div>'
    '<div class=\\"stat-value\\" id=\\"det-unassigned-count\\">'
    "{detection_initial['new_unassigned']} {_det_pct_html}"
    '</div>'
    '<div class=\\"stat-value-sub\\">Avg <span id=\\"det-unassigned-avg\\">'
    "{detection_365d['avg_unassigned_age_html']}"
    '</span> &middot; Newest <span id=\\"det-unassigned-newest\\">'
    "{detection_365d['newest_unassigned_age_html']}"
    '</span> &middot; Oldest <span id=\\"det-unassigned-oldest\\">'
    "{detection_365d['oldest_unassigned_age_html']}"
    '</span></div></div>',
    "py det stat-grid merged")

# ── Cases stat-grid template: merge into sub-line (BEFORE UNASSN) ────────────
py = sub1(py,
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassigned cases</div>'
    '<div class=\\"stat-value\\" id=\\"cases-unassigned-count\\">'
    "{cases_initial['unassigned_cases']} {_cases_pct_html}"
    '</div></div>\n'
    '                <div class="stat"><div class="stat-label">Avg unassigned age (365d)</div>'
    '<div class="stat-value">{age_value_html(avg_unassigned_case_age_365d)}</div></div>\n'
    '                <div class="stat"><div class="stat-label">Newest unassigned (365d)</div>'
    "<div class=\"stat-value\" id=\"cases-unassigned-newest\">{cases_365d['newest_unassigned_age_html']}</div></div>\n"
    '                <div class="stat"><div class="stat-label">Oldest unassigned (365d)</div>'
    "<div class=\"stat-value\" id=\"cases-unassigned-oldest\">{cases_365d['oldest_unassigned_age_html']}</div></div>",
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassn Cases</div>'
    '<div class=\\"stat-value\\" id=\\"cases-unassigned-count\\">'
    "{cases_initial['unassigned_cases']} {_cases_pct_html}"
    '</div>'
    '<div class=\\"stat-value-sub\\">Avg <span id=\\"cases-unassigned-avg\\">'
    "{cases_365d['avg_unassigned_age_html']}"
    '</span> &middot; Newest <span id=\\"cases-unassigned-newest\\">'
    "{cases_365d['newest_unassigned_age_html']}"
    '</span> &middot; Oldest <span id=\\"cases-unassigned-oldest\\">'
    "{cases_365d['oldest_unassigned_age_html']}"
    '</span></div></div>',
    "py cases stat-grid merged")

# ── Leads stat-grid template: merge into sub-line (BEFORE UNASSN) ────────────
py = sub1(py,
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassigned leads</div>'
    '<div class=\\"stat-value\\">'
    '{len(unassigned_leads)} {_leads_pct_html}'
    '</div></div>\n'
    '                <div class=\\"stat\\"><div class=\\"stat-label\\">Avg unassigned age</div>'
    '<div class=\\"stat-value\\">{age_value_html(leads_avg_age)}</div></div>\n'
    '                <div class="stat"><div class="stat-label">Newest unassigned</div>'
    '<div class="stat-value">{age_value_html(newest_unassigned_lead_age)}</div></div>\n'
    '                <div class="stat"><div class="stat-label">Oldest unassigned</div>'
    '<div class="stat-value">{age_value_html(oldest_unassigned_lead_age)}</div></div>',
    '<div class=\\"stat\\"><div class=\\"stat-label\\">Unassn Leads</div>'
    '<div class=\\"stat-value\\">'
    '{len(unassigned_leads)} {_leads_pct_html}'
    '</div>'
    '<div class=\\"stat-value-sub\\">Avg <span>'
    '{age_value_html(leads_avg_age)}'
    '</span> &middot; Newest <span>'
    '{age_value_html(newest_unassigned_lead_age)}'
    '</span> &middot; Oldest <span>'
    '{age_value_html(oldest_unassigned_lead_age)}'
    '</span></div></div>',
    "py leads stat-grid merged")

# ── UNASSN in remaining stat-label templates (all SKIP after merges) ──────────
for old_t, new_t in [
    ('Unassigned detections',     'Unassn Detections'),
    ('Unassigned cases',          'Unassn Cases'),
    ('Unassigned leads',          'Unassn Leads'),
    ('Avg unassigned age (365d)', 'Avg Unassn Age (365d)'),
    ('Newest unassigned (365d)',  'Newest Unassn (365d)'),
    ('Oldest unassigned (365d)',  'Oldest Unassn (365d)'),
    ('Avg unassigned age',        'Avg Unassn Age'),
    ('Newest unassigned',         'Newest Unassn'),
    ('Oldest unassigned',         'Oldest Unassn'),
]:
    py = sub1(py,
        f'<div class=\\"stat-label\\">{old_t}</div>',
        f'<div class=\\"stat-label\\">{new_t}</div>',
        f"py stat-label: {old_t}")

# h3 det-unassigned-title rename
py = sub1(py,
    '<h3 class=\\"muted\\" id=\\"det-unassigned-title\\">Unassigned Detections</h3>',
    '<h3 class=\\"muted\\" id=\\"det-unassigned-title\\">Unassn Detections</h3>',
    "py h3 det-unassigned-title")

# Table header (NOT removed by stat-grid merges — needs explicit rename)
py = sub1(py,
    '<th>Category</th><th>Unassigned</th>\\n                            <th>Newest</th><th>Oldest</th>',
    '<th>Category</th><th>Unassn</th>\\n                            <th>Newest</th><th>Oldest</th>',
    "py table header Unassn")

# ── JS template: add EYE constants + update toggles ──────────────────────────
eye_open_py_js   = EYE_OPEN.replace('\\', '\\\\').replace('`', '\\`')
eye_closed_py_js = EYE_CLOSED.replace('\\', '\\\\').replace('`', '\\`')

py = sub1(py,
    "        function processUnassignedTableHtml(rawHtml) {{",
    f"        const EYE_OPEN = `{eye_open_py_js}`;\n"
    f"        const EYE_CLOSED = `{eye_closed_py_js}`;\n\n"
    "        function processUnassignedTableHtml(rawHtml) {{",
    "py JS EYE constants")

py = sub1(py,
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.textContent = hidden ? 'Hide' : 'Show';\n"
    "        }}\n\n"
    "        function toggleCasesOverview()",
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;\n"
    "        }}\n\n"
    "        function toggleCasesOverview()",
    "py toggleDetOverview eye")

py = sub1(py,
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.textContent = hidden ? 'Hide' : 'Show';\n"
    "        }}\n\n"
    "        function setActiveRange(",
    "            art.style.display = hidden ? '' : 'none';\n"
    "            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;\n"
    "        }}\n\n"
    "        function setActiveRange(",
    "py toggleCasesOverview eye")

# ── JS template: renderDetections: add avg + title Unassn ────────────────────
py = sub1(py,
    "            if (payload365) {{\n"
    "                document.getElementById('det-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }}",
    "            if (payload365) {{\n"
    "                document.getElementById('det-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('det-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }}",
    "py renderDetections: avg sub-line")

py = sub1(py,
    "            document.getElementById('det-unassigned-title').textContent = `Unassigned Detections (${{range}})`;",
    "            document.getElementById('det-unassigned-title').textContent = `Unassn Detections (${{range}})`;",
    "py renderDetections title Unassn")

# ── JS template: renderCases: add avg ────────────────────────────────────────
py = sub1(py,
    "            if (payload365) {{\n"
    "                document.getElementById('cases-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }}",
    "            if (payload365) {{\n"
    "                document.getElementById('cases-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;\n"
    "                document.getElementById('cases-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;\n"
    "            }}",
    "py renderCases: avg sub-line")

# ── JS template: initCollapsibleSections: eye icons + initial collapse ────────
py = sub1(py,
    "            const collapsibleSections = new Set(['general overview', 'detections', 'new and unassigned cases', 'automated leads', 'activity']);\n",
    "            const collapsibleSections = new Set(['general overview', 'detections', 'cases', 'automated leads', 'activity']);\n"
    "            const initiallyCollapsed = new Set(['cases', 'automated leads', 'activity']);\n",
    "py collapsibleSections + initiallyCollapsed")

py = sub1(py,
    "                    indicator.textContent = expanded ? 'Hide' : 'Show';",
    "                    indicator.innerHTML = expanded ? EYE_CLOSED : EYE_OPEN;",
    "py collapse-indicator eye")

py = sub1(py,
    "                setExpanded(true);",
    "                setExpanded(!initiallyCollapsed.has(label));",
    "py initial collapse logic")

# ── write ─────────────────────────────────────────────────────────────────────
with open("falcon_overview.py", "w", encoding="utf-8") as f:
    f.write(py)
print("falcon_overview.py written.\n")

import ast
try:
    ast.parse(py)
    print("falcon_overview.py syntax: OK")
except SyntaxError as e:
    print(f"SYNTAX ERROR: {e}")
    sys.exit(1)

print("\nAll done.")
