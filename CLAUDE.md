# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ejecutar el script

```powershell
# Activar el entorno virtual (Windows)
.\.venv\Scripts\Activate.ps1

# Instalar dependencia (solo openpyxl)
pip install -r requirements.txt

# Ejecutar (salida por defecto: <dir_csv>/<nombre_csv>-export/<nombre_csv>.xlsx)
python twistlock_export.py -i <fichero_twistlock.csv>

# Ejecutar con nombre de salida personalizado (incluir .xlsx)
python twistlock_export.py -i <fichero_twistlock.csv> -o mi_export.xlsx

# Ver ayuda completa
python twistlock_export.py -h
```

Dependencia externa única: `openpyxl` (para el `.xlsx`). No hay tests
automatizados ni linter configurado.

## Arquitectura

Un único script `twistlock_export.py` con pipeline lineal:

```
parse_csv() -> group_and_build() -> export_xlsx()
```

**`parse_csv`** — lee el CSV de Twistlock con `csv.DictReader` (encoding `utf-8-sig` para BOM de Windows) y descarta todas las filas con `Type=OS`.

**`image_ref`** — reconstruye la ruta legible de la imagen como `Registry/Repository:Tag` (fallback al campo `Id`). Necesario porque `Id` no es uniforme entre scopes de export: en `registry` contiene la ruta completa, pero en `images` contiene el digest `sha256:...`. `Hostname`/`Target` salen de aquí, no de `Id`.

**`group_and_build`** — clave de agrupación: `(Id, Packages, Package Version)`. Cada grupo produce una sola fila de bitácora. `Details` contiene una cabecera `"La versión {ver} de {pkg} tiene los siguientes CVEs afectados:"` seguida de una línea por CVE con su fix: `"CVE-xxx → actualizar a X.Y.Z"`, `"CVE-yyy → parche pendiente"` o `"CVE-zzz → sin parche disponible"`. La etiqueta la genera `format_fix_label` a partir de `Fix Status`. Los CVE IDs están **deduplicados** (preservando orden) y **filtrados a solo `CVE-*`** (se descartan GHSA/PRISMA); si no hay CVE-* en el grupo, fallback a lista plana sin fix info. El **CVE principal** del grupo —mayor severidad, y a igualdad mayor CVSS (`sev_rank` + `cvss_float`)— aporta `Threat Description`, `References` (URL NVD construida con `nvd_url`) y `CVSS Base`/`CVSS Score`. `Countermeasure` es un **mensaje genérico fijo** (`"Se recomienda actualizar {pkg} a la última versión disponible del proveedor y revisar las versiones de corrección indicadas en Details."`) — no depende del CVE, para no afirmar de más cuando hay CVEs sin parche. `Severity` se deja **vacío** intencionadamente: en la bitácora es una fórmula que se autocalcula desde el CVSS.

**Orden de salida**: dos bloques. Primero las entradas **con** score CVSS (CVSS desc); después las **sin** score, por severidad desc. Dentro de cada bloque, desempate por nombre de paquete. Así una Critical/High con CVSS=0 no queda por debajo de una Low.

**`export_xlsx`** — único exporter. Recibe la lista de dicts con las claves de `FIELDS`. Antepone `LEADING_COLS` (2 columnas vacías A/B) para que `ID` caiga en la columna C; cabeceras coloreadas, filas alternas, `wrap_text`, `freeze_panes="D2"` y anchos por columna (`col_widths`). En `main`, el export va en un `try/except PermissionError` que avisa si el fichero está abierto en Excel.

## Flujo de uso (no solo código)

1. Ejecutar el script sobre el CSV de Prisma → genera el `.xlsx`.
2. **Triaje manual** del `.xlsx` antes de pegar: validar que cada versión vulnerable es real y se sufre en el código; las que sean falso positivo se **borran del `.xlsx`**, dejando solo las confirmadas.
3. Copiar las filas confirmadas y pegarlas en la bitácora desde la columna A; después **estirar (arrastrar) las fórmulas propias de la bitácora** sobre las filas pegadas para que recalculen.

## Decisiones de diseño importantes

**Columnas alineadas a la bitácora**: `FIELDS` replica el orden exacto de la Bitácora de Vulnerabilidades corporativa (hoja `Vulnerabilities`), de `ID` (col C) hasta `Finish Date` (col AL). `LEADING_COLS` antepone 2 columnas vacías (A y B) para que `ID` quede en la columna **C**, igual que la bitácora; así el copy-paste se hace desde la columna A. Si cambia el orden o el set de columnas de la bitácora, actualizar `FIELDS`/`LEADING_COLS` y los anchos en `col_widths` (`export_xlsx`).

**Identidad de la imagen (`image_ref`)**: `Hostname`/`Target` se reconstruyen desde `Registry/Repository:Tag` y NO desde `Id`, porque `Id` es el digest `sha256:...` en los export de scope `images`. Registry/Repository/Tag están en ambos scopes; si faltaran, fallback a `Id`.

**Valores fijos del proyecto**: `State=Open`, `Type=Application`, `Domain=Configuration Error`, `ASVS ID=ASVS-14.2.1` están hardcodeados — son constantes para todos los exports de este proyecto (confirmado). Reutilizar el script en otro proyecto requeriría parametrizarlos.

**Countermeasure genérica**: se eligió un mensaje fijo (no derivado del Fix Status) para "no pillarse los dedos": el detalle de versiones de fix por CVE ya vive en `Details`, y un mensaje genérico no afirma que exista parche cuando algún CVE es `deferred`/sin fix.

**Columnas con fórmula en la bitácora (NO rellenar)**: la hoja `Vulnerabilities` autocalcula 5 columnas; el export las deja **vacías** a propósito para no pisarlas. Al pegar y **estirar las fórmulas** de la bitácora sobre las filas nuevas, se recalculan solas: `C` ID (`=CONCATENATE("<PREFIJO>_"...ROW())`), `I` COE (VLOOKUP de IT Development Area), `P` Severity (IF sobre CVSS Score), `R` Category ASVS (VLOOKUP de ASVS ID), `T` OWASP Top 10 (VLOOKUP de ASVS ID). Por eso el script rellena `ASVS ID` y `CVSS Base/Score` (que alimentan esas fórmulas) pero deja vacíos `Severity`, `Category ASVS`, `OWASP Top 10`, `COE` e `ID`.

**Deduplicación de CVEs**: Prisma emite una fila por cada `Package Path` donde aparece el paquete. Un mismo paquete en N ficheros `.deps.json` repite cada CVE N veces. `group_and_build` deduplica con un `set` + lista ordenada. Sin esto, `Details` sale con CVEs repetidos.

**CVSS=0.00**: Prisma Cloud exporta 0.00 cuando NVD aún no ha puntuado el CVE. El script distingue dos casos según el año extraído del CVE ID: año actual → `"Pendiente de valoración NVD/NIST (CVE reciente)"`, años anteriores → `"Sin puntuación CVSS en NVD"`. El mismo valor va a `CVSS Base` y `CVSS Score`.

**Encoding en Windows**: La consola de Windows usa cp1251 por defecto, que no soporta caracteres españoles ni símbolos Unicode. El script reconfigura `sys.stdout` y `sys.stderr` a UTF-8 al inicio. Los strings del argparse `--help` deben evitar caracteres fuera de ASCII (sin `→`, `━`, `é`, `ó`, etc.) porque argparse escribe directamente a stdout antes de que la reconfiguración pueda actuar en algunos contextos.

**Salida**: Sin `-o`, crea `{stem_del_input}-export/{stem_del_input}.xlsx` junto al CSV de entrada. Con `-o <ruta.xlsx>`, escribe directamente en la ruta indicada (relativa al directorio del CSV si no es absoluta); crea directorios intermedios si no existen. En ambos casos sobreescribe si ya existe.

## Columnas esperadas en el CSV de entrada

Obligatorias (acceso directo, `KeyError` si faltan): `Id`, `Packages`, `Package Version`, `CVE ID`. Accedidas de forma tolerante con `.get()` (no rompen si faltan): `Type` (sin ella no se filtra OS), `CVSS`, `Severity`, `Description`, `Fix Status`, `Vulnerability Link`, y `Registry`/`Repository`/`Tag` (para `image_ref`; sin ellas, `Hostname`/`Target` caen al campo `Id`).
