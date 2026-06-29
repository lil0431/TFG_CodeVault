# CodeVault

CodeVault es una aplicación para analizar archivos binarios y ayudar en tareas de ingeniería inversa.

La herramienta automatiza parte del trabajo inicial del analista: extrae ensamblador y pseudocódigo, busca funciones sospechosas, genera grafos, calcula un nivel de riesgo y crea informes con ayuda de modelos de inteligencia artificial.

CodeVault no sustituye al analista. Su objetivo es ordenar la información y facilitar la primera fase del análisis.

---

## Funcionalidades

- Análisis estático de binarios.
- Extracción de ensamblador y pseudocódigo con Ghidra.
- Análisis estructural con Radare2.
- Generación de grafos con Graphviz.
- Puntuación de riesgo por función.
- Consulta a la base NIST NVD para relacionar hallazgos con vulnerabilidades conocidas.
- Análisis asistido por IA usando Gemini o Groq.
- Generación de informes en JSON y PDF.
- Uso desde interfaz web o desde consola.

---

## Arquitectura

El proyecto se divide en tres partes:

### Frontend

Interfaz web desarrollada con HTML, CSS y JavaScript.

Permite al usuario iniciar sesión, subir binarios, elegir opciones de análisis y descargar los resultados.

### Backend

Servidor desarrollado en Java con Spring Boot.

Se encarga de gestionar usuarios, proteger el acceso, guardar los análisis y lanzar el motor de análisis en Python.

### Motor de análisis

Módulo desarrollado en Python.

Ejecuta las herramientas de análisis, procesa los resultados, consulta servicios externos y genera los informes finales.

---

## Requisitos

Antes de ejecutar la aplicación es necesario tener instalado:

- Python 3.10 o superior.
- Java JDK 17 o superior.
- Maven.
- Ghidra.
- Radare2.
- Graphviz.
- wkhtmltopdf.

También se recomienda usar Linux, especialmente Ubuntu.

---

## Instalación

### Motor Python

```bash
pip install -r requirements.txt
```

### Backend Java

```bash
mvn clean install
mvn spring-boot:run
```

Por defecto, la aplicación web se ejecutará en:

```text
https://localhost:8443
```

---

## Variables de entorno

Para usar los modelos de IA, es necesario configurar las claves de API:

```bash
export GEMINI_API_KEY="tu_clave"
export GROQ_API_KEY="tu_clave"
```

Si no se configuran, el análisis con IA no estará disponible.

---

## Uso desde la web

1. Iniciar sesión.
2. Subir el binario.
3. Elegir las opciones de análisis.
4. Lanzar el proceso.
5. Consultar el estado desde el panel.
6. Descargar el informe en PDF o JSON.

---

## Uso desde consola

El motor de análisis también puede ejecutarse sin la interfaz web:

```bash
python3 tfg_orchestrator.py ruta_al_binario \
  --scan \
  --score \
  --graph \
  --explain \
  --ai-vulns \
  --exploit \
  --mitigate \
  --ai-engine gemini
```

También puede usarse Groq:

```bash
python3 tfg_orchestrator.py ruta_al_binario \
  --scan \
  --score \
  --graph \
  --explain \
  --ai-vulns \
  --exploit \
  --mitigate \
  --ai-engine groq
```

---

## Opciones principales

- `--scan`: activa el escaneo local.
- `--score`: calcula la puntuación de riesgo.
- `--graph`: genera grafos.
- `--explain`: genera una explicación técnica.
- `--ai-vulns`: busca posibles vulnerabilidades con IA.
- `--exploit`: genera orientación para el análisis de explotación.
- `--mitigate`: propone medidas de corrección.
- `--ai-engine`: selecciona el motor de IA: `gemini` o `groq`.

---

## Resultados

CodeVault genera principalmente dos archivos:

### JSON

Contiene los datos estructurados del análisis: funciones, hallazgos, puntuaciones, pseudocódigo y metadatos.

### PDF

Informe final con la información más importante: resumen del binario, funciones críticas, grafos, explicación técnica y recomendaciones.

---

## Limitaciones

- No ejecuta los binarios.
- No sustituye a herramientas de depuración como GDB.
- Puede generar falsos positivos.
- Los resultados de IA deben revisarse manualmente.
- Los binarios ofuscados o empaquetados pueden no analizarse correctamente.
- Las guías de explotación son orientativas.

---

## Tecnologías usadas

- Java
- Spring Boot
- Python
- HTML
- CSS
- JavaScript
- Ghidra
- Radare2
- Graphviz
- NIST NVD
- Gemini
- Groq
- wkhtmltopdf

---

## Uso responsable

CodeVault debe usarse únicamente en entornos autorizados, educativos o de auditoría legítima.

---

## Autora

Nawal Boukarssanna Bouazaoui

Trabajo de Fin de Grado:  
**CodeVault: Framework híbrido de auditoría y análisis forense de binarios asistido por inteligencia artificial**
