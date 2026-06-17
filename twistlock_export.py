#!/usr/bin/env python3
"""
twistlock_export.py

Convierte el CSV de vulnerabilidades exportado desde Prisma Cloud (Twistlock)
al formato de la Bitácora de Vulnerabilidades corporativa.

Genera tres archivos en una carpeta <nombre_input>-export/:
  - .txt   : Informe de texto legible (solo campos con valor)
  - .csv   : Columnas de la bitácora en orden, separado por ; para copy-paste
  - .xlsx  : Excel con las columnas de la bitácora, cabeceras coloreadas

Uso:
    python twistlock_export.py -i <fichero.csv>
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

# Forzar UTF-8 en stdout/stderr para evitar errores de codepage en Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import openpyxl
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False


CURRENT_YEAR = date.today().year

# Columnas de la Bitácora de Vulnerabilidades corporativa, en orden exacto
# desde "ID" hasta "Resolution Date". El export replica esta estructura para
# permitir copy-paste directo: pega haciendo clic en la celda de la columna ID.
# Las columnas no mapeadas se generan vacías para respetar el alineamiento.
FIELDS = [
    "ID",
    "Hostname",
    "AB",
    "IT Development Area",
    "COE",
    "State",
    "Service",
    "Origin",
    "Network",
    "Type",
    "Vulnerability Title",
    "Severity",
    "Domain",
    "Category ASVS",
    "ASVS ID",
    "OWASP Top 10",
    "PCI Status",
    "Threat Description",
    "Details",
    "Target",
    "Detection Date",
    "Countermeasure",
    "Environment",
    "Production Affected?",
    "References",
    "CVSS Base",
    "CVSS Score",
    "Easy of Exploit",
    "CVSS Version",
    "CVSS Vector",
    "Resolution Date",
    "XX/XX/26",  # columna AH de la bitácora (placeholder de fecha); va vacía
]

# Columnas A y B de la bitácora, anteriores a "ID". En el CSV/XLSX se anteponen
# vacías para que "ID" quede en la columna C y el copy-paste pueda hacerse desde
# la columna A de la bitácora. No forman parte de los datos (siempre vacías).
LEADING_COLS = ["", ""]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_cve_year(cve_id: str) -> int:
    m = re.search(r"CVE-(\d{4})-", cve_id, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def is_cve(vuln_id: str) -> bool:
    """True si el identificador es un CVE (descarta GHSA, PRISMA, etc.)."""
    return vuln_id.strip().upper().startswith("CVE-")


# Orden de severidad para elegir el "CVE principal" del grupo
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def sev_rank(row: dict) -> int:
    return SEV_RANK.get((row.get("Severity") or "").strip().lower(), 0)


def nvd_url(cve_id: str) -> str:
    """URL canónica de NVD a partir del CVE ID."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id.strip()}"


def cvss_float(row: dict) -> float:
    """Lee la columna CVSS de forma tolerante (texto vacío o inválido -> 0.0)."""
    raw = (row.get("CVSS") or "").strip()
    try:
        return float(raw)
    except ValueError:
        return 0.0


def get_cvss_display(cvss_score: float, cve_id: str) -> str:
    """Devuelve el score CVSS o un texto explicativo cuando no está disponible.

    El número usa coma decimal (formato español de la bitácora): 7.8 -> "7,8".
    """
    if cvss_score > 0:
        return str(cvss_score).replace(".", ",")
    year = extract_cve_year(cve_id)
    if year >= CURRENT_YEAR:
        return "Pendiente de valoración NVD/NIST (CVE reciente)"
    return "Sin puntuación CVSS en NVD"


def format_countermeasure(fix_status: str, package: str) -> str:
    """Convierte el Fix Status de Prisma en una contramedida legible."""
    fix_status = (fix_status or "").strip()
    if fix_status.lower().startswith("fixed in"):
        version = fix_status[len("fixed in"):].strip()
        return f"Actualizar {package} a versión {version}"
    if fix_status.lower() == "deferred":
        return "Sin parche disponible actualmente (estado: deferred)"
    if fix_status.lower() == "needed":
        return "Aplicar parche cuando esté disponible"
    return fix_status


def parse_csv(input_path: Path):
    """
    Lee el CSV de Prisma Cloud. Devuelve (filas_no_OS, num_filas_OS).
    El conteo de OS se hace aquí sobre registros CSV reales (no líneas físicas)
    para ser robusto frente a descripciones con saltos de línea embebidos.
    """
    rows = []
    os_count = 0
    with open(input_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Type", "").strip() == "OS":
                os_count += 1
                continue
            rows.append(row)
    return rows, os_count


def group_and_build(rows: list) -> list:
    """
    Agrupa por (contenedor, paquete, versión) y construye una fila de bitácora
    por grupo. Los CVEs se deduplican preservando orden de aparición y se
    descartan identificadores no-CVE (GHSA, PRISMA). El CVE principal del grupo
    (mayor severidad; a igualdad, mayor CVSS) aporta Threat Description,
    Countermeasure, CVSS Base/Score y References. Severity se deja vacío: la
    bitácora lo autocalcula desde el CVSS.

    La salida se ordena por criticidad descendente (Critical, High, Medium,
    Low) y, al final, las entradas sin score CVSS / informativas. A igualdad
    de criticidad, por CVSS descendente; como desempate, por nombre de paquete.
    """
    groups = defaultdict(list)
    for row in rows:
        key = (row["Id"], row["Packages"], row["Package Version"])
        groups[key].append(row)

    entries = []  # (crit_rank, cvss_val, pkg, row) para ordenar al final
    for (container_id, pkg, version), vulns in sorted(groups.items(), key=lambda x: x[0][1].lower()):
        # CVE IDs deduplicados, solo CVE-*, preservando orden de aparición
        seen = set()
        cve_ids = []
        for v in vulns:
            vid = v["CVE ID"].strip()
            if is_cve(vid) and vid not in seen:
                seen.add(vid)
                cve_ids.append(vid)

        # Pool para elegir el "CVE principal": solo CVEs si los hay.
        # Fallback defensivo: si el grupo no tuviera ningún CVE, usar todos.
        cve_vulns = [v for v in vulns if is_cve(v["CVE ID"])]
        pool = cve_vulns if cve_vulns else vulns
        # Principal = mayor severidad; a igualdad de severidad, mayor CVSS.
        # Así Severity, CVSS, Threat Description y References salen del mismo
        # CVE y reflejan el peor caso del grupo de forma coherente.
        top = sorted(pool, key=lambda v: (sev_rank(v), cvss_float(v)), reverse=True)[0]
        top_cve = top["CVE ID"].strip()

        # Si no quedó ningún CVE (caso límite), no perder los identificadores
        ids_display = cve_ids or list(dict.fromkeys(v["CVE ID"].strip() for v in vulns))

        title = (
            f"{ids_display[0]} en {pkg} ({version})"
            if len(ids_display) == 1
            else f"Múltiples CVEs en {pkg} ({version})"
        )

        # Threat Description: descripción del CVE de mayor criticidad del grupo.
        threat = (top.get("Description", "") or "").strip()

        cvss_display = get_cvss_display(cvss_float(top), top_cve)
        references = nvd_url(top_cve) if is_cve(top_cve) else top.get("Vulnerability Link", "").strip()

        # Valores fijos para todos los exports de este proyecto:
        # State=Open, Type=Application, Domain=Configuration Error,
        # ASVS ID=ASVS-14.2.1. Si se reutilizara el script en otro proyecto con
        # otros valores, habría que parametrizarlos aquí.
        row = dict.fromkeys(FIELDS, "")
        row.update({
            "Hostname": container_id,
            "State": "Open",
            "Type": "Application",
            "Vulnerability Title": title,
            # Severity se deja vacío: la bitácora lo autocompleta a partir del CVSS.
            "Domain": "Configuration Error",
            "ASVS ID": "ASVS-14.2.1",
            "Threat Description": threat,
            "Details": ", ".join(ids_display),
            "Target": container_id,
            "Countermeasure": format_countermeasure(top.get("Fix Status", ""), pkg),
            "References": references,
            "CVSS Base": cvss_display,
            "CVSS Score": cvss_display,
        })

        # Clave de criticidad: las entradas sin score CVSS caen al fondo
        # (crit_rank 0), por debajo de Low. El resto usa el rango de severidad.
        cvss_val = cvss_float(top)
        crit_rank = sev_rank(top) if cvss_val > 0 else 0
        entries.append((crit_rank, cvss_val, pkg.lower(), row))

    entries.sort(key=lambda e: (-e[0], -e[1], e[2]))
    return [row for _, _, _, row in entries]


# ---------------------------------------------------------------------------
# Exporters
# ---------------------------------------------------------------------------

def export_txt(rows: list, output_path: Path) -> None:
    """Informe legible: solo muestra los campos con valor (omite columnas vacías)."""
    sep = "=" * 90
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("BITÁCORA DE VULNERABILIDADES — EXPORT PRISMA CLOUD\n")
        f.write(f"Generado: {date.today().strftime('%d/%m/%Y')}  |  Entradas: {len(rows)}\n")
        f.write(f"{sep}\n\n")
        for i, row in enumerate(rows, 1):
            f.write(f"{sep}\n")
            f.write(f"  #{i:03d}  {row['Vulnerability Title']}\n")
            f.write(f"{sep}\n")
            for field in FIELDS:
                value = row.get(field, "")
                if not value:
                    continue
                f.write(f"  {field:<22}: {value}\n")
            f.write("\n")
    print(f"  [TXT]  {output_path.name}")


def export_csv(rows: list, output_path: Path) -> None:
    """
    CSV con las columnas de la bitácora, separador ; para copy-paste.
    Antepone 2 columnas vacías (A y B de la bitácora) para que 'ID' caiga en
    la columna C y el copy-paste pueda hacerse desde la columna A.
    """
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(LEADING_COLS + FIELDS)
        for row in rows:
            writer.writerow(["", ""] + [row.get(field, "") for field in FIELDS])
    print(f"  [CSV]  {output_path.name}")


def export_xlsx(rows: list, output_path: Path) -> None:
    if not XLSX_AVAILABLE:
        print("  [XLSX] OMITIDO — ejecuta: pip install openpyxl")
        return

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Bitácora Export"

    # Estilos
    hdr_fill  = PatternFill("solid", fgColor="1F4E79")
    hdr_font  = Font(bold=True, color="FFFFFF", size=10)
    alt_fill  = PatternFill("solid", fgColor="DCE6F1")
    wrap_top  = Alignment(wrap_text=True, vertical="top")
    center    = Alignment(horizontal="center", vertical="center")
    thin      = Side(style="thin", color="B0B0B0")
    border    = Border(left=thin, right=thin, top=thin, bottom=thin)

    # Columnas en orden de la bitácora: las 2 iniciales (A/B) + FIELDS.
    # Offset de 2 para que "ID" quede en la columna C, igual que la bitácora.
    all_cols = LEADING_COLS + FIELDS

    # Cabecera
    for col, field in enumerate(all_cols, 1):
        cell = ws.cell(row=1, column=col, value=field)
        cell.fill   = hdr_fill
        cell.font   = hdr_font
        cell.alignment = center
        cell.border = border
    ws.row_dimensions[1].height = 22

    # Datos (las 2 columnas iniciales quedan vacías)
    for row_idx, row in enumerate(rows, 2):
        fill = alt_fill if row_idx % 2 == 0 else None
        values = ["", ""] + [row.get(field, "") for field in FIELDS]
        for col, value in enumerate(values, 1):
            cell = ws.cell(row=row_idx, column=col, value=value)
            cell.alignment = wrap_top
            cell.border    = border
            if fill:
                cell.fill = fill
        ws.row_dimensions[row_idx].height = 70

    # Anchos de columna (las columnas vacías mantienen un ancho discreto)
    col_widths = {
        "": 4,
        "ID": 10, "Hostname": 50, "AB": 10, "IT Development Area": 20,
        "COE": 18, "State": 8, "Service": 14, "Origin": 18, "Network": 12,
        "Type": 12, "Vulnerability Title": 42, "Severity": 10, "Domain": 20,
        "Category ASVS": 14, "ASVS ID": 14, "OWASP Top 10": 22, "PCI Status": 10,
        "Threat Description": 55, "Details": 40, "Target": 50,
        "Detection Date": 14, "Countermeasure": 42, "Environment": 14,
        "Production Affected?": 16, "References": 40, "CVSS Base": 16,
        "CVSS Score": 16, "Easy of Exploit": 14, "CVSS Version": 12,
        "CVSS Vector": 20, "Resolution Date": 14, "XX/XX/26": 12,
    }
    for col, field in enumerate(all_cols, 1):
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = col_widths.get(field, 14)

    # Congelar cabecera y las 3 primeras columnas (A, B, ID) al hacer scroll
    ws.freeze_panes = "D2"
    wb.save(output_path)
    print(f"  [XLSX] {output_path.name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="twistlock_export.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="twistlock_export - Conversor de vulnerabilidades Prisma Cloud a Bitacora corporativa",
        epilog="""\
QUE HACE
--------
  Lee el CSV de vulnerabilidades exportado desde Prisma Cloud (Twistlock),
  filtra los paquetes de sistema operativo (OS), agrupa los CVEs por paquete
  y genera tres archivos con las columnas de la Bitacora de Vulnerabilidades
  corporativa, listos para copy-paste.

QUE NECESITA
------------
  - Python 3.8 o superior
  - Dependencia externa: openpyxl (solo para el .xlsx)
      pip install -r requirements.txt
  - El CSV exportado desde Prisma Cloud con las columnas estandar de
    Twistlock (CVE ID, Type, Packages, Package Version, CVSS, Severity,
    Description, Fix Status, Vulnerability Link, Id).

QUE EXPORTA
-----------
  Crea una carpeta en el MISMO directorio del CSV de entrada, llamada
  <nombre_del_csv>-export/, con tres archivos (mismo nombre base):

    .txt   Informe legible. Solo muestra los campos con valor.
    .csv   Columnas de la bitacora en orden, separado por ; (copy-paste).
    .xlsx  Excel con las columnas de la bitacora y cabeceras coloreadas.

  El .csv y .xlsx replican las columnas de la bitacora desde la columna A
  hasta la AH: anteponen 2 columnas vacias (A y B) para que 'ID' quede en
  la columna C. Pega desde la columna A; las columnas no mapeadas quedan
  vacias y respetan el alineamiento. Para conservar las formulas de la
  bitacora, usa Pegado especial -> Omitir celdas en blanco.

  Campos que se rellenan automaticamente:
    Hostname, State (Open), Type (Application), Vulnerability Title,
    Domain (Configuration Error), ASVS ID (ASVS-14.2.1), Threat Description,
    Details (CVEs unicos del paquete), Target, Countermeasure, References,
    CVSS Base, CVSS Score.
  (Severity se deja vacio: la bitacora lo autocalcula desde el CVSS.)

LOGICA DE PROCESAMIENTO
-----------------------
  - Excluye filas con Type=OS (paquetes del sistema operativo).
  - Agrupa por (contenedor, paquete, version): 1 fila por paquete.
  - Details: CVE IDs unicos (deduplicados), solo CVE-* (descarta GHSA/PRISMA).
  - El CVE principal del grupo (mayor severidad; a igualdad, mayor CVSS)
    aporta Threat Description, Countermeasure, CVSS Base/Score y References.
  - Orden de salida: por criticidad descendente (Critical, High, Medium,
    Low) y, al final, las entradas sin score CVSS.
  - CVSS (con coma decimal, p.ej. 7,8):
      > 0        -> score numerico real
      año actual -> "Pendiente de valoracion NVD/NIST (CVE reciente)"
      años ant.  -> "Sin puntuacion CVSS en NVD"

EJEMPLO
-------
  python twistlock_export.py -i twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.csv

  -> 335 filas totales: 171 OS (excluidas) + 164 procesadas
  -> 36 entradas agrupadas (una por paquete vulnerable)
""",
    )
    parser.add_argument(
        "-i", "--input", required=True, metavar="CSV",
        help="Ruta al CSV exportado desde Prisma Cloud / Twistlock",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"ERROR: archivo no encontrado — {input_path}")
        raise SystemExit(1)

    # La salida se crea en una carpeta nueva en el MISMO directorio del CSV de
    # entrada, con el nombre <nombre_del_csv>-export/. Si ya existe, se reutiliza
    # y los archivos se sobreescriben.
    output_dir = input_path.parent / f"{input_path.stem}-export"
    output_dir.mkdir(exist_ok=True)

    print(f"\nInput : {input_path.name}")
    print(f"Output: {output_dir.name}/\n")

    rows_raw, os_count = parse_csv(input_path)
    bitacora_rows = group_and_build(rows_raw)

    print(f"Filas en el CSV       : {len(rows_raw) + os_count}")
    print(f"Excluidas (OS)        : {os_count}")
    print(f"Procesadas            : {len(rows_raw)}")
    print(f"Entradas en bitacora  : {len(bitacora_rows)} (agrupadas por paquete)\n")

    stem = input_path.stem
    try:
        export_txt(bitacora_rows,  output_dir / f"{stem}.txt")
        export_csv(bitacora_rows,  output_dir / f"{stem}.csv")
        export_xlsx(bitacora_rows, output_dir / f"{stem}.xlsx")
    except PermissionError as e:
        print(f"\nERROR: no se pudo escribir '{e.filename}'.")
        print("       Probablemente lo tienes abierto en Excel. Ciérralo y reejecuta.")
        raise SystemExit(1)

    print(f"\nExport completado en: {output_dir}")


if __name__ == "__main__":
    main()
