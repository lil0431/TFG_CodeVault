import argparse
import subprocess
import os
import json
import sys
import re
import time
import requests
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from concurrent.futures import ThreadPoolExecutor
import markdown
import pdfkit
import base64

# --- CONFIGURACIÓN DE IA ---
try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[!] Aviso: Librería google-genai no instalada. La IA Gemini no funcionará.")

# ──────────────────────────────────────────────────────────────────────────────
# Límites de contexto por motor (en caracteres del JSON de funciones)
# ──────────────────────────────────────────────────────────────────────────────
MAX_CONTEXT_CHARS = {
    "gemini": 800_000,
    "groq":   100_000,
}

# ──────────────────────────────────────────────────────────────────────────────
# Pesos base de severidad del motor de reglas
# (se enriquecen con CVSS real de NIST NVD en RiskScorer)
# ──────────────────────────────────────────────────────────────────────────────
SEVERITY_BASE = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   15,
    "LOW":       5,
    "INFO":      2,
}


def truncate_functions(functions, max_chars):
    full = json.dumps(functions, indent=2)
    if len(full) <= max_chars:
        return functions
    truncated, total = [], 0
    for fn in functions:
        chunk = json.dumps(fn, indent=2)
        if total + len(chunk) > max_chars:
            print(f"[!] Contexto truncado a {len(truncated)} funciones "
                  f"({total} chars) para no superar el límite del motor.")
            break
        truncated.append(fn)
        total += len(chunk)
    return truncated


# ==========================================
# FASE 1: EXTRACCIÓN (GHIDRA)
# ==========================================
class GhidraExtractor:
    def __init__(self, ghidra_path):
        self.ghidra_path = ghidra_path

    def extract(self, binary_path, asm_only=False):
        nombre_script = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        analyze_headless = os.path.join(self.ghidra_path, "support", nombre_script)
        
        project_dir      = os.path.abspath("./ghidra_projects")
        binary_abs_path  = os.path.abspath(binary_path)
        script_dir       = os.path.dirname(os.path.abspath(__file__))

        if not os.path.exists(project_dir):
            os.makedirs(project_dir)

        print("[*] FASE 1: Extrayendo código con Ghidra...")
        cmd = [
            analyze_headless, project_dir, "TFG_PROJ",
            "-import", binary_abs_path, "-scriptPath", script_dir,
            "-postScript", "ExportFuncs.java",
            "-deleteProject", "-overwrite", "-readOnly"
        ]
        os.environ["_JAVA_OPTIONS"] = "-Xmx4G -Xms1G"
        process = subprocess.run(cmd, capture_output=True, text=True)

        functions      = []
        recording_mode = None
        current_data   = {"name": "", "address": "", "asm": [], "pseudo_c": [], "calls": []}

        for line in process.stdout.splitlines():
            if "---START_FUNC:" in line:
                name         = line.split("---START_FUNC:")[1].split("---")[0]
                current_data = {"name": name, "address": "N/A",
                                "asm": [], "pseudo_c": [], "calls": []}
            elif "---ADDR:" in line:
                current_data["address"] = line.split("---ADDR:")[1].split("---")[0]

            # ── Call graph markers ──────────────────────────────────────────
            elif "---START_CALLS---" in line:
                recording_mode = "CALLS"
            elif "---END_CALLS---" in line:
                recording_mode = None
            elif recording_mode == "CALLS":
                clean = line.split(">")[-1].strip() if ">" in line else line.strip()
                if clean.startswith("CALL:"):
                    callee = clean[5:].strip()
                    if callee and callee not in current_data["calls"]:
                        current_data["calls"].append(callee)
            # ───────────────────────────────────────────────────────────────

            elif "---START_ASM---" in line:
                recording_mode = "ASM"
            elif "---END_ASM---" in line:
                recording_mode = None
            elif "---START_C---" in line:
                recording_mode = "C"
            elif "---END_C---" in line:
                recording_mode = None
            elif "---END_FUNC---" in line:
                if current_data["name"]:
                    if asm_only:
                        current_data.pop("pseudo_c", None)
                    functions.append(current_data.copy())
            elif recording_mode in ("ASM", "C"):
                clean_line = line.split(">")[-1].strip() if ">" in line else line.strip()
                if clean_line:
                    if recording_mode == "ASM":
                        current_data["asm"].append(clean_line)
                    elif recording_mode == "C" and not asm_only:
                        current_data["pseudo_c"].append(clean_line)

        return functions


# ==========================================
# FASE 2: MOTOR DE REGLAS LOCALES
# ==========================================
class LocalAuditor:
    def __init__(self, rules_path="rules.json"):
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)["vulnerabilidades"]
        else:
            print("[!] rules.json no encontrado. Saltando motor local.")
            self.rules = []

    def audit(self, functions):
        print("[*] FASE 2: Auditando localmente con motor de firmas...")
        findings = []
        for func in functions:
            code_combined = "\n".join(func.get("pseudo_c", [])).lower()
            asm_combined  = "\n".join(func.get("asm", [])).lower()
            for rule in self.rules:
                for kw in rule["keywords"]:
                    if kw in code_combined or kw in asm_combined:
                        findings.append({
                            "funcion":        func["name"],
                            "vulnerabilidad": rule["nombre"],
                            "cwe_id":         rule.get("id", ""),
                            "severidad":      rule.get("severidad", "MEDIUM"),
                            "evidencia":      kw,
                            "consejo":        rule["consejo"],
                        })
        return findings


# ==========================================
# FASE 2b: RISK SCORING (NIST NVD)
# ==========================================
class RiskScorer:
    """
    Puntúa cada función detectada por el motor de reglas.

    Algoritmo:
      score_func = Σ (peso_severidad_local + cvss_nvd * 3) por cada hallazgo en esa función
      El CVSS real se obtiene de la API pública NIST NVD v2 usando el CWE-ID.
      Si la API no responde, se usa solo el peso local (degradación elegante).

    API usada: https://services.nvd.nist.gov/rest/json/cves/2.0
               Parámetro: cweId=CWE-XXX  — pública, sin autenticación requerida.
    """

    NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Caché en memoria para no repetir llamadas al mismo CWE en un mismo análisis
    _cvss_cache: dict = {}

    def _fetch_cvss_for_cwe(self, cwe_id: str) -> float:
        """
        Devuelve el CVSS promedio de los últimos CVEs del CWE dado.
        Retorna 0.0 si no se puede contactar la API o el CWE no tiene CVEs.
        """
        if not cwe_id or not cwe_id.startswith("CWE-"):
            return 0.0
        if cwe_id in self._cvss_cache:
            return self._cvss_cache[cwe_id]

        try:
            params = {
                "cweId":           cwe_id,
                "resultsPerPage":  20,   # últimos 20 CVEs de ese CWE
                "startIndex":      0,
            }
            r = requests.get(self.NVD_API, params=params, timeout=8)
            if r.status_code != 200:
                self._cvss_cache[cwe_id] = 0.0
                return 0.0

            data  = r.json()
            items = data.get("vulnerabilities", [])
            scores = []
            for item in items:
                metrics = item.get("cve", {}).get("metrics", {})
                # Intentamos CVSS v3.1 primero, luego v3.0, luego v2
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        base = metrics[key][0].get("cvssData", {}).get("baseScore")
                        if base is not None:
                            scores.append(float(base))
                            break

            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            self._cvss_cache[cwe_id] = avg
            # Pequeña pausa para respetar el rate-limit de NIST (5 req/s sin API key)
            time.sleep(0.25)
            return avg

        except Exception:
            self._cvss_cache[cwe_id] = 0.0
            return 0.0

    def score(self, functions: list, findings: list) -> list:
        """
        Devuelve lista de dicts con score por función, ordenada de mayor a menor.
        """
        print("[*] FASE 2b: Calculando Risk Score (enriquecido con NIST NVD)...")

        # Agrupar hallazgos por función
        func_findings: dict = {}
        for f in findings:
            func_findings.setdefault(f["funcion"], []).append(f)

        # CWEs únicos que necesitamos consultar
        unique_cwes = {f["cwe_id"] for f in findings if f.get("cwe_id", "").startswith("CWE-")}
        print(f"    → Consultando NIST NVD para {len(unique_cwes)} CWEs únicos...")
        for cwe in unique_cwes:
            self._fetch_cvss_for_cwe(cwe)   # rellena la caché

        scored = []
        for func in functions:
            fname    = func["name"]
            hits     = func_findings.get(fname, [])
            asm_size = len(func.get("asm", []))
            calls_n  = len(func.get("calls", []))

            base_score = 0
            breakdown  = []
            seen_cwes  = set()

            for hit in hits:
                sev_pts  = SEVERITY_BASE.get(hit.get("severidad", "MEDIUM"), 15)
                cwe_id   = hit.get("cwe_id", "")
                cvss_avg = self._cvss_cache.get(cwe_id, 0.0)
                nvd_pts  = round(cvss_avg * 3, 1)   # escala CVSS 0-10 → contribución 0-30

                # Evitamos contar el mismo CWE dos veces en la misma función
                if cwe_id not in seen_cwes:
                    base_score += sev_pts + nvd_pts
                    seen_cwes.add(cwe_id)

                breakdown.append({
                    "vulnerabilidad": hit["vulnerabilidad"],
                    "cwe_id":         cwe_id,
                    "severidad":      hit.get("severidad", "?"),
                    "cvss_avg_nvd":   cvss_avg,
                    "pts_aportados":  sev_pts + nvd_pts,
                })

            # Bonus por complejidad: funciones grandes o muy llamadas suben un poco
            complexity_bonus = min(10, asm_size // 20) + min(5, calls_n)
            total = round(min(100, base_score + complexity_bonus), 1)

            scored.append({
                "funcion":          fname,
                "score":            total,
                "nivel":            _score_to_level(total),
                "n_hallazgos":      len(hits),
                "asm_instrucciones": asm_size,
                "llama_a":          calls_n,
                "detalle":          breakdown,
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored


def _score_to_level(score: float) -> str:
    if score >= 70: return "CRÍTICO"
    if score >= 45: return "ALTO"
    if score >= 20: return "MEDIO"
    if score >  0:  return "BAJO"
    return "LIMPIO"


# ==========================================
# FASE 2c: GRAFO DE LLAMADAS (ESTRUCTURAL)
# ==========================================
import graphviz
import os
import r2pipe

class CallGraphAnalyzer:
    BG_MAP = {"CRÍTICO": "#1e3a8a", "ALTO": "#3b82f6", "MEDIO": "#93c5fd", "BAJO": "#dbeafe", "LIMPIO": "#f8fafc"}
    BORDER_MAP = {"CRÍTICO": "#ffffff", "ALTO": "#ffffff", "MEDIO": "#1e293b", "BAJO": "#1e293b", "LIMPIO": "#475569"}

    def render(self, functions: list, scored: list, output_path: str) -> str:
        if not functions: return ""
        dot = graphviz.Digraph(format='png')
        dot.attr(rankdir='TB', splines='ortho', nodesep='0.8', ranksep='1.0', bgcolor='#ffffff', dpi='200')
        score_map = {s["funcion"]: s for s in scored}
        func_names = {f["name"] for f in functions}

        for func in functions:
            name = func["name"]
            if name.startswith("_") and name not in ["_start", "main"]: continue
            nivel = score_map.get(name, {}).get("nivel", "LIMPIO")
            bg_color = self.BG_MAP.get(nivel, "#f8fafc")
            border_color = self.BORDER_MAP.get(nivel, "#475569")
            font_color = "#ffffff" if nivel in ["CRÍTICO", "ALTO"] else "#1e293b"
            dot.node(name, name, shape='box', style='filled,rounded', fillcolor=bg_color, color=border_color, fontcolor=font_color, fontname='Helvetica-Bold', fontsize='12', margin='0.25,0.15')

        for func in functions:
            caller = func["name"]
            if caller.startswith("_") and caller not in ["_start", "main"]: continue
            for callee in func.get("calls", []):
                callee_clean = callee.replace(" (GhidraScript)", "").strip()
                if callee_clean not in func_names:
                    dot.node(callee_clean, callee_clean, shape='box', style='filled,dashed,rounded', fillcolor='#f1f5f9', color='#94a3b8', fontcolor='#475569', fontname='Helvetica', fontsize='11', margin='0.15,0.1')
                dot.edge(caller, callee_clean, color="#64748b", arrowsize="0.8", penwidth="1.5")
        
        base_path = output_path.replace('.png', '')
        try:
            dot.render(base_path, cleanup=True)
            return output_path
        except: return ""

# ==========================================
# FASE 2d: GRAFO DE FLUJO DE CONTROL (RADARE2 CFG)
# ==========================================
class RadareCFGAnalyzer:
    """Extrae el Control Flow Graph real de Radare2 (Bloques ASM y saltos lógicos)"""
    def render_cfg(self, binary_path: str, func_name: str, output_path: str) -> str:
        print(f"[*] FASE 2d: Generando Grafo de Flujo (CFG) de '{func_name}' con Radare2...")
        if not os.path.exists(binary_path): return ""
        try:
            r2 = r2pipe.open(binary_path, flags=['-2'])
            r2.cmd('aaaa')
            r2.cmd(f's {func_name}')
            dot_content = r2.cmd('agfd') # Extraer CFG en formato DOT
            r2.quit()

            if not dot_content or len(dot_content) < 10: return ""

            dot_tmp_path = output_path.replace('.png', '.dot')
            with open(dot_tmp_path, 'w') as f: f.write(dot_content)

            import subprocess
            subprocess.run(['dot', '-Tpng', dot_tmp_path, '-o', output_path], check=True)
            os.remove(dot_tmp_path)
            print(f"    [+] CFG de Radare2 guardado en: {output_path}")
            return output_path
        except Exception as e:
            print(f"[!] Error generando CFG con Radare2: {e}")
            return ""
# ==========================================
# FASE 3: MÓDULO DE IA DINÁMICA
# ==========================================
class AIAnalyzer:
    def __init__(self, api_key, engine="gemini"):
        self.engine  = engine
        self.api_key = api_key

        if engine == "gemini":
            from google import genai
            self.client = genai.Client(api_key=api_key)
        elif engine == "groq":
            from groq import Groq
            self.client = Groq(api_key=api_key)

    def _build_prompt(self, functions, args, scored=None):
        prompt = """
        Eres un analista experto en reversing, explotación binaria y CTFs.

        Tu objetivo NO es generar un informe corporativo.

        Tu objetivo es explicar el binario como si estuvieras guiando
        a alguien durante un proceso real de reversing en Ghidra o IDA.

        Habla de forma natural y técnica al mismo tiempo.

        NO uses un tono excesivamente formal ni académico.

        Explica las cosas como lo haría un investigador de seguridad
        enseñándole a otra persona cómo entiende el binario.

        Prioriza:

        - razonamiento
        - explicación paso a paso
        - interpretación del código
        - ejemplos
        - contexto técnico
        - relación entre ASM y pseudo-C
        - comportamiento real en memoria

        NO hagas listas gigantes innecesarias.

        NO hagas descripciones genéricas.

        NO inventes vulnerabilidades.

        Si algo parece sospechoso pero no es concluyente, dilo claramente.

        Cuando expliques algo importante:

        - explica por qué llama la atención
        - qué implicaciones tiene
        - cómo se detectaría en reversing real
        - qué ocurre realmente en memoria o registros

        Responde en Markdown técnico pero legible y didáctico.
        """

        # Inyectar el top-5 de funciones más peligrosas para que la IA priorice
        if scored:
            top5 = scored[:5]
            prompt += "\n\n# CONTEXTO DE RIESGO (calculado antes de este análisis)\n"
            prompt += "Las siguientes funciones tienen el mayor Risk Score. Prioriza su análisis:\n"
            for s in top5:
                prompt += (f"- **{s['funcion']}** — Score {s['score']}/100 "
                           f"({s['nivel']}) — {s['n_hallazgos']} hallazgos\n")

        if args.explain:
            prompt += """

        # EXPLICACIÓN

        Explica el flujo real del programa paso a paso.

        Para las funciones importantes explica:

        - qué hacen realmente
        - qué datos manejan
        - cómo se conectan entre sí
        - qué buffers o estructuras usan
        - qué instrucciones ASM son relevantes
        - qué comportamiento sospechoso aparece

        Concéntrate en:

        - main
        - funciones custom
        - validaciones
        - llamadas indirectas
        - lógica importante

        No expliques funciones triviales de libc.

        Explica el análisis de forma clara y entendible, como un profesor de reversing ayudando a seguir el flujo del binario.
        """

        if args.ai_vulns:
            prompt += """

        # VULNERABILIDADES

        Busca vulnerabilidades reales basadas en el código.

        Evita listar problemas genéricos si no aparecen claramente.

        Analiza especialmente:

        - overflows
        - format strings
        - corrupción de memoria
        - punteros peligrosos
        - validaciones débiles
        - lectura/escritura arbitraria
        - llamadas inseguras

        Para cada vulnerabilidad explica:

        - dónde ocurre
        - por qué ocurre
        - qué controla el usuario
        - impacto real
        - dificultad de explotación

        Relaciona siempre la explicación con el código y ASM relevante.
        """

        if args.exploit:
            prompt += """

        # EXPLOTACIÓN

        Explica cómo podría explotarse el binario paso a paso.

        Incluye:

        - cómo interactuar con el programa
        - qué input provoca el fallo
        - qué ocurre en memoria
        - registros importantes
        - cómo reproducir el crash
        - cómo verlo en GDB

        Incluye ejemplos simples de:

        - breakpoints
        - info registers
        - x/20gx
        - payloads
        - cyclic patterns

        Explica el proceso como si estuvieras guiando a alguien durante un reversing práctico.
        """

        if args.mitigate:
            prompt += """

    # MITIGACIONES

    Explica cómo corregir las vulnerabilidades encontradas.

    Incluye:

    - validaciones correctas
    - código C seguro
    - límites de buffers
    - mitigaciones modernas
    - hardening

    Explica específicamente:

    - cómo evitar la vulnerabilidad exacta
    - por qué la corrección funciona
    - qué protecciones ayudarían

    Incluye ejemplos pequeños y claros en C.
    """

        max_chars  = MAX_CONTEXT_CHARS.get(self.engine, 30000)
        safe_funcs = truncate_functions(functions, max_chars)
        prompt    += f"\n\n# CÓDIGO ANALIZADO\n{json.dumps(safe_funcs, indent=2)}"
        return prompt

    def analyze(self, functions, args, scored=None):
        print(f"[*] FASE 3: Consultando a la IA ({self.engine.upper()})...")
        prompt = self._build_prompt(functions, args, scored=scored)

        if self.engine == "gemini":
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.3)
            )
            return response.text

        elif self.engine == "groq":
            response = self.client.chat.completions.create(
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=4092,
            )
            return response.choices[0].message.content


# ==========================================
# FASE 4: RENDERIZADO DEL REPORTE
# ==========================================
class ReportGenerator:

    @staticmethod
    def _level_badge(level: str) -> str:
        # Paleta azul CodeVault — pastel sobre blanco, legible en escala de grises
        styles = {
            "CRÍTICO": "background:#fee2e2;color:#7f1d1d;border:1px solid #fca5a5;",
            "ALTO":    "background:#ffedd5;color:#7c2d12;border:1px solid #fdba74;",
            "MEDIO":   "background:#fef9c3;color:#713f12;border:1px solid #fde047;",
            "BAJO":    "background:#dcfce7;color:#14532d;border:1px solid #86efac;",
            "LIMPIO":  "background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;",
        }
        style = styles.get(level, styles["LIMPIO"])
        return (f'<span style="{style}padding:2px 10px;border-radius:4px;'
                f'font-size:11.5px;font-weight:700;letter-spacing:0.04em;">{level}</span>')

    @staticmethod
    def _img_to_base64(img_path: str) -> str:
        with open(img_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("utf-8")

    @staticmethod
    def create_pdf(json_data, local_findings, ai_report, scored,
                   graph_path, cfg_path,output_name):
        print(f"[*] FASE 4: Generando PDF ({output_name}.pdf)...")

        # ── Sección Risk Score ────────────────────────────────────────────────
        risk_html = ""
        if scored:
            risk_html += """
            <h2>📊 Risk Score por Función</h2>
            <p style='color:#555;font-size:14px;'>
              Score calculado combinando la severidad local de cada regla con el CVSS
              promedio obtenido en tiempo real de la
              <strong>API pública NIST NVD</strong> para cada CWE detectado.
              Rango: 0–100.
            </p>
            <table>
              <thead>
                <tr>
                  <th>#</th><th>Función</th><th>Score</th><th>Nivel</th>
                  <th>Hallazgos</th><th>Instrucciones ASM</th><th>Llama a N func.</th>
                </tr>
              </thead>
              <tbody>
            """
            for i, s in enumerate(scored, 1):
                badge = ReportGenerator._level_badge(s["nivel"])
                risk_html += (
                    f"<tr>"
                    f"<td>{i}</td>"
                    f"<td><code>{s['funcion']}</code></td>"
                    f"<td><strong>{s['score']}</strong></td>"
                    f"<td>{badge}</td>"
                    f"<td>{s['n_hallazgos']}</td>"
                    f"<td>{s['asm_instrucciones']}</td>"
                    f"<td>{s['llama_a']}</td>"
                    f"</tr>\n"
                )
            risk_html += "</tbody></table>\n"

            # Detalle de CWEs con CVSS NVD
            risk_html += "<h3>Detalle de CWEs y CVSS NVD</h3><table>"
            risk_html += ("<thead><tr>"
                          "<th>Función</th><th>CWE</th><th>Vulnerabilidad</th>"
                          "<th>Severidad</th><th>CVSS NVD (avg)</th><th>Pts aportados</th>"
                          "</tr></thead><tbody>")
            for s in scored:
                for d in s["detalle"]:
                    cvss_str = str(d["cvss_avg_nvd"]) if d["cvss_avg_nvd"] > 0 else "N/A"
                    risk_html += (
                        f"<tr>"
                        f"<td><code>{s['funcion']}</code></td>"
                        f"<td><code>{d['cwe_id']}</code></td>"
                        f"<td>{d['vulnerabilidad']}</td>"
                        f"<td>{d['severidad']}</td>"
                        f"<td>{cvss_str}</td>"
                        f"<td>{d['pts_aportados']}</td>"
                        f"</tr>\n"
                    )
            risk_html += "</tbody></table><hr>"

        # ── Sección Call Graph ────────────────────────────────────────────────
        graph_html = ""
        if graph_path and os.path.exists(graph_path):
            b64 = ReportGenerator._img_to_base64(graph_path)
            graph_html = f"""
            <h2>🕸️ Grafo de Llamadas entre Funciones</h2>
            <p style='color:#555;font-size:14px;'>
              Grafo dirigido generado a partir de las referencias de tipo CALL extraídas
              por Ghidra. El color de cada nodo refleja su Risk Score.
              El tamaño es proporcional a su <em>in-degree</em>
              (cuántas funciones lo invocan).
            </p>
            <div style="text-align:center; margin: 20px 0;">
              <img src="data:image/png;base64,{b64}"
                   style="max-width:100%;border-radius:10px;
                          box-shadow:0 4px 12px rgba(0,0,0,0.18);" />
            </div>
            <hr>
            """
	# ── Sección Call Graph y CFG ────────────────────────────────────────────────
        graph_html = ""
        if graph_path and os.path.exists(graph_path):
            b64 = ReportGenerator._img_to_base64(graph_path)
            graph_html += f"""
            <h2>🕸️ Esquema Topológico de Llamadas</h2>
            <div style="text-align:center; margin: 20px 0;">
              <img src="data:image/png;base64,{b64}" style="max-width:100%;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.18);" />
            </div>
            """
            
        if cfg_path and os.path.exists(cfg_path):
            b64_cfg = ReportGenerator._img_to_base64(cfg_path)
            graph_html += f"""
            <h2>🔀 Grafo de Flujo de Control (CFG) - Función 'main'</h2>
            <p style='color:#555;font-size:14px;'>Generado nativamente con Radare2. Muestra los bloques básicos de ensamblador y las ramificaciones condicionales (verde = True, rojo = False).</p>
            <div style="text-align:center; margin: 20px 0;">
              <img src="data:image/png;base64,{b64_cfg}" style="max-width:100%;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.18);" />
            </div>
            <hr>
            """
        else:
            graph_html += "<hr>"
        # ── Sección detecciones locales ───────────────────────────────────────
        local_html = ""
        if local_findings:
            local_html += "<h2>🛡️ Detecciones del Motor de Reglas Local</h2><ul>"
            for f in local_findings:
                local_html += (
                    f"<li><strong>{f['vulnerabilidad']}</strong> en "
                    f"<code>{f['funcion']}</code> "
                    f"(Evidencia: <code>{f['evidencia']}</code>). "
                    f"<em>Mitigación: {f['consejo']}</em></li>\n"
                )
            local_html += "</ul><hr>"

        # ── Sección IA ────────────────────────────────────────────────────────
        ai_html = ""
        if ai_report:
            ai_md   = markdown.markdown(ai_report, extensions=["fenced_code", "tables"])
            ai_html = f"<h2>🤖 Análisis Inteligente y Tutoría</h2>{ai_md}<hr>"

        # ── Anexo código ──────────────────────────────────────────────────────
        annex_md = "## 📝 Anexo: Código Extraído\n"
        for func in json_data["functions"]:
            annex_md += f"### Función: `{func['name']}`\n"
            if func.get("pseudo_c"):
                annex_md += "```c\n" + "\n".join(func["pseudo_c"]) + "\n```\n"
            else:
                annex_md += "*No se pudo extraer pseudo-C.*\n"
        annex_html = markdown.markdown(annex_md, extensions=["fenced_code", "tables"])

        # ── CSS ───────────────────────────────────────────────────────────────
        # Paleta CodeVault (alineada al index.html de la plataforma):
        #   Acento principal : #3b82f6   Azul brillante : #60a5fa
        #   Texto oscuro     : #1e293b   Gris texto     : #64748b
        #   Fondo documento  : #ffffff   Fondo alterno  : #f0f6ff
        #   Borde suave      : #bfdbfe
        css = """
        <style>
        /* ── Reset y base ───────────────────────────────── */
        *{box-sizing:border-box;margin:0;padding:0;}

        body{
            font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
            background:#ffffff;
            color:#1e293b;
            font-size:15px;
            line-height:1.8;
            margin:0;
            padding:0;
        }

        /* ── Cabecera corporativa ────────────────────────── */
        .report-header{
            background:#ffffff;
            border-bottom:4px solid #3b82f6;
            padding:40px 55px 28px;
        }
        .report-header .brand{
            font-size:11px;
            letter-spacing:0.18em;
            text-transform:uppercase;
            color:#3b82f6;
            font-weight:700;
            margin-bottom:10px;
        }
        .report-header h1{
            font-size:26px;
            font-weight:700;
            color:#0f172a;
            letter-spacing:-0.01em;
            border:none;
            margin:0 0 6px;
            padding:0;
        }
        .report-header .subtitle{
            font-size:13px;
            color:#64748b;
            margin:0;
        }
        .report-header .meta-row{
            display:flex;
            gap:30px;
            margin-top:18px;
            padding-top:16px;
            border-top:1px solid #bfdbfe;
        }
        .report-header .meta-item{
            font-size:12px;
            color:#475569;
        }
        .report-header .meta-item strong{
            display:block;
            font-size:11px;
            text-transform:uppercase;
            letter-spacing:0.1em;
            color:#3b82f6;
            margin-bottom:2px;
        }

        /* ── Cuerpo ─────────────────────────────────────── */
        .report-body{
            padding:40px 55px 60px;
        }

        /* ── Headings ───────────────────────────────────── */
        h2{
            font-size:17px;
            font-weight:700;
            color:#0f172a;
            text-transform:uppercase;
            letter-spacing:0.07em;
            margin:48px 0 14px;
            padding-bottom:8px;
            border-bottom:2px solid #3b82f6;
        }
        h3{
            font-size:14px;
            font-weight:600;
            color:#1e293b;
            margin:28px 0 10px;
            padding-left:10px;
            border-left:3px solid #93c5fd;
        }
        h4{
            font-size:13px;
            font-weight:600;
            color:#334155;
            margin:18px 0 6px;
        }
        p{
            margin:10px 0;
            color:#334155;
        }

        /* ── Tablas ─────────────────────────────────────── */
        table{
            width:100%;
            border-collapse:collapse;
            margin:18px 0 28px;
            font-size:13px;
        }
        thead tr{
            background:#1e40af;
            color:#ffffff;
        }
        thead th{
            padding:10px 14px;
            text-align:left;
            font-weight:600;
            letter-spacing:0.04em;
            font-size:12px;
            text-transform:uppercase;
            border:none;
        }
        tbody tr{
            border-bottom:1px solid #dbeafe;
        }
        tbody tr:nth-child(even){
            background:#f0f6ff;
        }
        tbody tr:hover{
            background:#dbeafe;
        }
        td{
            padding:9px 14px;
            color:#1e293b;
            border:none;
            vertical-align:top;
        }

        /* ── Código ─────────────────────────────────────── */
        pre{
            background:#f8faff;
            border:1px solid #bfdbfe;
            border-left:3px solid #3b82f6;
            border-radius:4px;
            padding:16px 18px;
            font-size:12.5px;
            line-height:1.6;
            overflow-x:auto;
            margin:14px 0;
            color:#1e293b;
        }
        code{
            background:#eff6ff;
            color:#1d4ed8;
            font-size:12.5px;
            padding:2px 6px;
            border-radius:3px;
            font-family:'Courier New',Courier,monospace;
        }
        pre code{
            background:none;
            color:inherit;
            padding:0;
        }

        /* ── Separadores ─────────────────────────────────── */
        hr{
            border:none;
            border-top:1px solid #dbeafe;
            margin:40px 0;
        }

        /* ── Listas ─────────────────────────────────────── */
        ul,ol{
            padding-left:20px;
            margin:10px 0 18px;
        }
        li{
            margin-bottom:6px;
            color:#334155;
            font-size:14px;
        }

        /* ── Blockquote ─────────────────────────────────── */
        blockquote{
            border-left:4px solid #3b82f6;
            background:#eff6ff;
            padding:12px 18px;
            margin:16px 0;
            border-radius:0 4px 4px 0;
            color:#334155;
            font-style:italic;
        }

        /* ── Nota ────────────────────────────────────────── */
        .note{
            font-size:12px;
            color:#94a3b8;
            margin-top:-8px;
            margin-bottom:14px;
        }

        /* ── Footer ──────────────────────────────────────── */
        .report-footer{
            margin-top:60px;
            padding-top:18px;
            border-top:2px solid #3b82f6;
            display:flex;
            justify-content:space-between;
            font-size:11px;
            color:#94a3b8;
            letter-spacing:0.04em;
        }
        </style>
        """

        import datetime
        fecha = datetime.datetime.now().strftime("%d/%m/%Y  %H:%M")

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  {css}
</head>
<body>

  <!-- ══ CABECERA CORPORATIVA ══════════════════════════════════════ -->
    <div class="report-header">
    <div class="brand">CodeVault · Análisis de Seguridad Binaria</div>
    <h1>Reporte de Auditoría — {json_data['binary']}</h1>
    <p class="subtitle">Análisis estático automatizado mediante Ghidra + Motor de Reglas + NIST NVD</p>
    <div class="meta-row">
      <div class="meta-item"><strong>Binario</strong>{json_data['binary']}</div>
      <div class="meta-item"><strong>Funciones analizadas</strong>{len(json_data['functions'])}</div>
      <div class="meta-item"><strong>Generado</strong>{fecha}</div>
      <div class="meta-item"><strong>Clasificación</strong>CONFIDENCIAL</div>
    </div>
  </div>

  <!-- ══ CUERPO ════════════════════════════════════════════════════ -->
  <div class="report-body">

    {risk_html}
    {graph_html}
    {local_html}
    {ai_html}
    {annex_html}

    <!-- Footer interno del documento -->
    <div class="report-footer">
      <span>CodeVault · Seguridad Binaria Automatizada</span>
      <span>CONFIDENCIAL — uso interno</span>
      <span>{fecha}</span>
    </div>

  </div>

</body>
</html>"""

        with open(f"{output_name}.html", "w", encoding="utf-8") as fh:
            fh.write(html)

        import platform

        directorio_script = os.path.dirname(os.path.abspath(__file__))

        try:
            if platform.system() == "Windows":
                ruta_exe = os.path.join(directorio_script, "wkhtmltopdf.exe")
                configuracion = pdfkit.configuration(wkhtmltopdf=ruta_exe)
                
                pdfkit.from_file(
                    f"{output_name}.html", 
                    f"{output_name}.pdf",
                    options={"enable-local-file-access": None},
                    configuration=configuracion
                )
            else:
                pdfkit.from_file(
                    f"{output_name}.html", 
                    f"{output_name}.pdf",
                    options={"enable-local-file-access": None}
                )
            print("[+] PDF generado con éxito.")
        except Exception as e:
            print(f"[!] wkhtmltopdf no encontrado o error: {e}")
            print(f"[+] Se ha guardado el .html en su lugar: {output_name}.html")


# ==========================================
# CLI Y EJECUCIÓN PRINCIPAL
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Navaja Suiza TFG",
        description="Analizador de Binarios ELF — Ghidra + Reglas + Risk Score + Call Graph + IA",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("binary", help="Ruta al archivo binario a analizar")

    extract_group = parser.add_argument_group("Opciones de Extracción")
    extract_group.add_argument("--asm-only", action="store_true",
                               help="Extraer SOLO ensamblador (sin pseudo-C)")

    local_group = parser.add_argument_group("Opciones de Auditoría Local")
    local_group.add_argument("--scan", action="store_true",
                             help="Escanear contra reglas de seguridad (rules.json)")

    analysis_group = parser.add_argument_group("Análisis Estático Avanzado")
    analysis_group.add_argument("--score", action="store_true",
                                help="Calcular Risk Score por función (requiere --scan)")
    analysis_group.add_argument("--graph", action="store_true",
                                help="Generar grafo de llamadas coloreado por riesgo")

    ai_group = parser.add_argument_group("Opciones de Análisis IA")
    ai_group.add_argument("--explain",  action="store_true", help="Explicar qué hace el código")
    ai_group.add_argument("--ai-vulns", action="store_true", help="Detectar vulnerabilidades (IA)")
    ai_group.add_argument("--exploit",  action="store_true", help="Guía de explotación")
    ai_group.add_argument("--mitigate", action="store_true", help="Mitigaciones en C")

    ai_cfg = parser.add_argument_group("Configuración del Motor de IA")
    ai_cfg.add_argument("--ai-engine", choices=["gemini", "groq"], default="gemini",
                        help="Motor de IA (default: gemini)")
    ai_cfg.add_argument("--api-key", type=str, default=None,
                        help="API Key (si no se indica, usa la del código)")

    args = parser.parse_args()

    # ── Rutas y claves ─────────────────────────────────────────────────────────
    GHIDRA_DIR     = "ghidra_11.0.3_PUBLIC"
    GEMINI_API_KEY = ""
    GROQ_API_KEY   = ""

    api_key = args.api_key
    if not api_key:
        api_key = GEMINI_API_KEY if args.ai_engine == "gemini" else GROQ_API_KEY

    binary_name = os.path.basename(args.binary)
    output_base = f"reporte_{binary_name}"

    # ── FASE 1: Extracción ─────────────────────────────────────────────────────
    extractor      = GhidraExtractor(GHIDRA_DIR)
    extracted_funcs = extractor.extract(args.binary, args.asm_only)

    json_data = {"binary": binary_name, "functions": extracted_funcs}
    print(f"[+] Funciones extraídas: {len(extracted_funcs)}")

    # ── FASE 2: Auditoría local ────────────────────────────────────────────────
    local_findings = []
    if args.scan:
        auditor        = LocalAuditor()
        local_findings = auditor.audit(extracted_funcs)
        print(f"[+] Auditoría local: {len(local_findings)} hallazgos")

    # ── FASE 2b: Risk Scoring ─────────────────────────────────────────────────
    scored = []
    if args.score:
        if not args.scan:
            print("[!] --score requiere --scan para tener hallazgos. Activando --scan automáticamente.")
            auditor        = LocalAuditor()
            local_findings = auditor.audit(extracted_funcs)
        scorer = RiskScorer()
        scored = scorer.score(extracted_funcs, local_findings)
        # Guardar scoring en JSON aparte
        with open(f"{output_base}_scores.json", "w", encoding="utf-8") as fh:
            json.dump(scored, fh, indent=4, ensure_ascii=False)
        print(f"[+] Risk Scores calculados. Top función: "
              f"{scored[0]['funcion']} ({scored[0]['score']}/100)" if scored else "[+] Sin funciones puntuadas.")

    # ── FASE 2c y 2d: Grafos ──────────────────────────────────────────────────
    graph_path = ""
    cfg_path = ""
    if args.graph:
        cga        = CallGraphAnalyzer()
        graph_path = cga.render(extracted_funcs, scored, f"{output_base}_callgraph.png")
        
        # Generar el CFG de Radare2 para el main
        rcfg       = RadareCFGAnalyzer()
        cfg_path   = rcfg.render_cfg(args.binary, "main", f"{output_base}_cfg.png")

    # ── FASE 3: IA ─────────────────────────────────────────────────────────────
    ai_report  = ""
    needs_ai   = args.explain or args.ai_vulns or args.exploit or args.mitigate

    if needs_ai:
        try:
            ai        = AIAnalyzer(api_key, engine=args.ai_engine)
            ai_report = ai.analyze(extracted_funcs, args, scored=scored if scored else None)
            print(f"[+] Análisis IA completado ({len(ai_report)} chars)")
        except Exception as e:
            print(f"[!] ERROR en el motor de IA ({args.ai_engine}): {e}")
            print("    El reporte se generará sin análisis IA.")

    # ── FASE 4: Reporte ────────────────────────────────────────────────────────
    # Inyectar todos los resultados en el JSON final antes de guardarlo
    json_data["local_findings"] = local_findings
    json_data["risk_scores"] = scored
    json_data["ai_report"] = ai_report

    with open(f"{output_base}.json", "w", encoding="utf-8") as fh:
        json.dump(json_data, fh, indent=4, ensure_ascii=False)
    print(f"[+] Reporte JSON consolidado y guardado.")
    
    ReportGenerator.create_pdf(
        json_data, local_findings, ai_report,
        scored, graph_path, cfg_path, output_base
    )

    print("\n[+] PROCESO COMPLETADO SATISFACTORIAMENTE.")
