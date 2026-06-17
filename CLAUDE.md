# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ejecutar el script

```powershell
# Activar el entorno virtual (Windows)
.\.venv\Scripts\Activate.ps1

# Ejecutar
python twistlock_export.py -i <fichero_twistlock.csv>

# Ver ayuda completa
python twistlock_export.py -h
```

## Setup del entorno

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt   # solo instala openpyxl
```

No hay tests automatizados ni linter configurado.

## Arquitectura

Un único script `twistlock_export.py` con pipeline lineal:

```
parse_csv() -> group_and_build() -> export_txt() / export_csv() / export_xlsx()
```

**`parse_csv`** — lee el CSV de Twistlock con `csv.DictReader` (encoding `utf-8-sig` para BOM de Windows) y descarta todas las filas con `Type=OS`.

**`group_and_build`** — clave de agrupación: `(Id, Packages, Package Version)`. Cada grupo produce una sola fila de bitácora. En `Details` se concatenan los CVE IDs **deduplicados** (preservando orden) y **filtrados a solo `CVE-*`** (se descartan GHSA/PRISMA). El **CVE principal** del grupo —mayor severidad, y a igualdad mayor CVSS (`sev_rank` + `cvss_float`)— aporta `Threat Description`, `Countermeasure`, `References` (URL NVD construida con `nvd_url`) y `CVSS Base`/`CVSS Score`. `Severity` se deja **vacío** intencionadamente: en la bitácora es una fórmula que se autocalcula desde el CVSS.

La salida se ordena por **criticidad descendente** (Critical→Low) y, al final, las entradas sin score CVSS (`crit_rank` 0). A igualdad, por CVSS y luego nombre de paquete.

**Exporters** — los tres reciben la misma lista de dicts con las claves de `FIELDS`. El TXT solo imprime campos con valor (omite las columnas vacías). El CSV/XLSX anteponen `LEADING_COLS` (2 columnas vacías) y llegan hasta `XX/XX/26` (col AH). El CSV usa `;` como separador (mismo que la bitácora); el XLSX usa `freeze_panes="D2"` y filas alternas. En `main`, los exports van en un `try/except PermissionError` que avisa si el fichero está abierto en Excel.

## Decisiones de diseño importantes

**Columnas alineadas a la bitácora**: `FIELDS` replica el orden exacto de la Bitácora de Vulnerabilidades corporativa (hoja `Vulnerabilities`), de `ID` hasta `XX/XX/26` (col AH, placeholder de fecha, va vacía). `LEADING_COLS` antepone 2 columnas vacías (A y B) para que `ID` quede en la columna **C**, igual que la bitácora; así el copy-paste se hace desde la columna A. El CSV/XLSX generan todas las columnas (las no mapeadas vacías). Si cambia el orden o el set de columnas de la bitácora, actualizar `FIELDS`/`LEADING_COLS` y los anchos en `col_widths` (`export_xlsx`).

**Valores fijos del proyecto**: `State=Open`, `Type=Application`, `Domain=Configuration Error`, `ASVS ID=ASVS-14.2.1` están hardcodeados — son constantes para todos los exports de este proyecto (confirmado). Reutilizar el script en otro proyecto requeriría parametrizarlos.

**Columnas con fórmula en la bitácora (NO rellenar)**: la hoja `Vulnerabilities` autocalcula 5 columnas; el export las deja **vacías** a propósito para no pisarlas al pegar con "omitir celdas en blanco": `C` ID (`=CONCATENATE("<PREFIJO>_"...ROW())`), `G` COE (VLOOKUP de IT Development Area), `N` Severity (IF sobre CVSS Score), `P` Category ASVS (VLOOKUP de ASVS ID), `R` OWASP Top 10 (VLOOKUP de ASVS ID). Por eso el script rellena `ASVS ID` y `CVSS Base/Score` (que alimentan esas fórmulas) pero deja vacíos `Severity`, `Category ASVS`, `OWASP Top 10`, `COE` e `ID`.

**Deduplicación de CVEs**: Prisma emite una fila por cada `Package Path` donde aparece el paquete. Un mismo paquete en N ficheros `.deps.json` repite cada CVE N veces. `group_and_build` deduplica con un `set` + lista ordenada. Sin esto, `Details` sale con CVEs repetidos.

**CVSS=0.00**: Prisma Cloud exporta 0.00 cuando NVD aún no ha puntuado el CVE. El script distingue dos casos según el año extraído del CVE ID: año actual → `"Pendiente de valoración NVD/NIST (CVE reciente)"`, años anteriores → `"Sin puntuación CVSS en NVD"`. El mismo valor va a `CVSS Base` y `CVSS Score`.

**Encoding en Windows**: La consola de Windows usa cp1251 por defecto, que no soporta caracteres españoles ni símbolos Unicode. El script reconfigura `sys.stdout` y `sys.stderr` a UTF-8 al inicio. Los strings del argparse `--help` deben evitar caracteres fuera de ASCII (sin `→`, `━`, `é`, `ó`, etc.) porque argparse escribe directamente a stdout antes de que la reconfiguración pueda actuar en algunos contextos.

**Campo ID vacío**: Se genera vacío intencionadamente porque en la bitácora la columna `ID` es una fórmula (`=CONCATENATE("<PREFIJO>_",...,ROW()...)`) que se autogenera. Si se pega con "omitir celdas en blanco", la fórmula se conserva.

**Carpeta de salida**: Siempre `{stem_del_input}-export/` junto al CSV de entrada. Si ya existe, se reutiliza y los ficheros se sobreescriben.

## Columnas esperadas en el CSV de entrada

El script accede por nombre a estas columnas de Twistlock: `Type`, `Id`, `Packages`, `Package Version`, `CVE ID`, `CVSS`, `Severity`, `Description`, `Fix Status`, `Vulnerability Link`. Si el CSV no tiene alguna de estas columnas el script fallará con `KeyError`.
