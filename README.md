# twistlock-export

Convierte el CSV de vulnerabilidades exportado desde **Prisma Cloud (Twistlock)**
al formato de la **Bitácora de Vulnerabilidades corporativa**, generando dos
archivos listos para copy-paste.

---

## Contenido del proyecto

```
twistlock-export/
├── twistlock_export.py          ← script principal
├── requirements.txt             ← sin dependencias externas
├── README.md                    ← este fichero
└── CLAUDE.md                    ← notas de arquitectura
```

---

## Requisitos

| Requisito | Versión mínima |
|-----------|----------------|
| Python    | 3.8            |

El script usa únicamente la biblioteca estándar de Python (`csv`, `argparse`,
`re`, `collections`, `datetime`, `pathlib`). **No hay dependencias externas.**

---

## Uso

```powershell
python twistlock_export.py -i <ruta_al_csv_de_prisma>
```

**Ejemplo con el fichero de este proyecto:**

```powershell
python twistlock_export.py -i "twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.csv"
```

**Salida esperada en consola:**

```
Input : twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.csv
Output: twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02-export/

Filas en el CSV       : 335
Excluidas (OS)        : 171
Procesadas            : 164
Entradas en bitacora  : 36 (agrupadas por paquete)

  [TXT]  twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.txt
  [CSV]  twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.csv

Export completado en: twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02-export
```

---

## Archivos generados

Los dos archivos se crean en una **carpeta nueva en el mismo directorio que el
CSV de entrada**, cuyo nombre es el del CSV más el sufijo `-export`. Si la carpeta
ya existe, se reutiliza y los archivos se sobreescriben.

```
twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02-export/
├── twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.txt
└── twistlock_registry_base_image_vulns_excluded_6_15_26_13_01_02.csv
```

| Formato | Uso recomendado |
|---------|-----------------|
| `.txt`  | Revisión rápida, lectura humana, adjunto a tickets (solo muestra campos con valor) |
| `.csv`  | **Copy-paste directo a la bitácora** (separador `;`, mismo que el original) |

### Copy-paste a la bitácora

El `.csv` replica **las columnas de la bitácora en orden exacto**, desde la
columna **A** hasta la **AH**. Antepone 2 columnas vacías (A y B) para que `ID`
quede en la columna **C**, igual que la bitácora. Las columnas que el script no
rellena se generan vacías para respetar el alineamiento.

**Cómo pegar:** abre el export, copia las filas de datos (sin la cabecera) y pega
haciendo clic en la celda de la **columna A** de la primera fila libre de la
bitácora. Cada valor cae en su columna.

### ⚠️ Respetar las fórmulas de la bitácora

La hoja `Vulnerabilities` de la bitácora **autocalcula 5 columnas con fórmulas**.
El export las deja **vacías a propósito** para no pisarlas:

| Col | Campo | Se calcula desde |
|-----|-------|------------------|
| C | ID | nº de fila (`ROW()`) |
| G | COE | IT Development Area |
| N | Severity | CVSS Score |
| P | Category ASVS | ASVS ID |
| R | OWASP Top 10 | ASVS ID |

Si pegas normal, las celdas vacías del export **borran** esas fórmulas. Para
conservarlas:

1. Asegúrate de que las filas destino ya tienen las fórmulas (arrástralas hacia
   abajo desde una fila existente si vas a usar filas nuevas).
2. Copia las filas de datos del export.
3. En la bitácora, **botón derecho → Pegado especial → marca "Omitir celdas en
   blanco"** → Aceptar.

Así las columnas vacías del export no sobreescriben las fórmulas, y estas
recalculan solas con los datos que sí se pegan (Severity desde el CVSS, Category
ASVS y OWASP desde el ASVS ID, etc.).

---

## Lógica de procesamiento

### 1. Filtrado de tipos

Se excluyen todas las filas con `Type = OS` (paquetes del sistema operativo).
Solo se procesan:

| Tipo Prisma | Descripción |
|-------------|-------------|
| `python`    | Paquetes Python (pip/wheels) |
| `nuget`     | Paquetes .NET / NuGet |
| `Application` | Vulnerabilidades a nivel de aplicación |

### 2. Agrupación por paquete

Las filas se agrupan por `(contenedor, paquete, versión)`. Cada grupo genera
**una sola fila** en la bitácora. Los CVEs del grupo se listan juntos en el
campo `Details`, **deduplicados** y preservando el orden de aparición.

> La deduplicación es necesaria porque Prisma repite el mismo CVE una vez por
> cada ruta de fichero (`Package Path`) donde detecta el paquete. Sin dedup,
> un paquete presente en 4 ficheros `.deps.json` listaría cada CVE 4 veces.

**Filtro de identificadores:** en `Details` solo se incluyen identificadores
`CVE-*`. Los `GHSA-*` (GitHub Security Advisory) y `PRISMA-*` se descartan.

**Orden de salida:** las entradas se ordenan por criticidad descendente
(Critical → High → Medium → Low) y, al final, las que no tienen score CVSS
(CVEs recientes sin valorar / informativas). A igualdad de criticidad se ordena
por CVSS descendente.

**Ejemplo:**  
`libxml2 2.9.10` tiene 17 CVEs en Prisma → 1 fila en la bitácora con todos los
CVE IDs (únicos) en Details, y el título
`Múltiples CVEs en libxml2 (2.9.10+dfsg-5ubuntu0.20.04.8)`.

Cuando el grupo tiene un único CVE, el título usa ese CVE directamente:
`CVE-2024-0056 en system.data.sqlclient (4.8.5)`.

### 3. Lógica CVSS

Los campos `CVSS Base` y `CVSS Score` corresponden al **CVE principal** del grupo
(mayor severidad; a igualdad, mayor CVSS). El mismo CVE aporta `Severity`,
`Threat Description` y `References`, de modo que todos son coherentes entre sí.

| Situación | Valor en bitácora |
|-----------|-------------------|
| CVSS > 0 en Prisma | Score numérico con coma decimal (ej. `8,7`) |
| CVSS = 0 y CVE del año en curso | `Pendiente de valoración NVD/NIST (CVE reciente)` |
| CVSS = 0 y CVE de años anteriores | `Sin puntuación CVSS en NVD` |

> **Nota:** Prisma Cloud exporta un único score numérico sin indicar la versión
> de CVSS (2.0, 3.1 o 4.0). Los scores del export son CVSS 3.1 (estándar NVD).
> La bitácora original usa CVSS 4.0 con vector completo — ese vector no está
> disponible en el CSV de Prisma y debe rellenarse manualmente si se requiere.

---

## Mapeo de campos

El export genera **todas las columnas de la bitácora** (de `ID` hasta la columna
`XX/XX/26`). Las que no aparecen abajo se generan **vacías**: unas las rellenas a
mano (`AB`, `IT Development Area`, `Service`, `Origin`, `Network`, `PCI Status`,
`Detection Date`, `Environment`, `Production Affected?`, `Easy of Exploit`,
`CVSS Version`, `CVSS Vector`, `Resolution Date`) y otras las autocalcula la
bitácora con fórmulas (`COE`, `Severity`, `Category ASVS`, `OWASP Top 10`, e `ID`
— ver sección "Respetar las fórmulas").

| Campo bitácora | Origen | Lógica |
|----------------|--------|--------|
| `ID` | — | Vacío (rellenar manualmente con el patrón de ID de la bitácora) |
| `Hostname` | `Id` | Ruta completa de la imagen del contenedor |
| `State` | — | Fijo: `Open` |
| `Type` | — | Fijo: `Application` |
| `Vulnerability Title` | `Packages` + `CVE ID` | `Múltiples CVEs en {pkg} ({ver})` o `{CVE} en {pkg} ({ver})` |
| `Severity` | — | **Vacío** (la bitácora lo autocompleta a partir del CVSS) |
| `Domain` | — | Fijo: `Configuration Error` |
| `ASVS ID` | — | Fijo: `ASVS-14.2.1` |
| `Threat Description` | `Description` | Descripción del CVE de mayor criticidad del grupo |
| `Details` | `CVE ID` + `Fix Status` | `La versión {ver} de {pkg} tiene los siguientes CVEs afectados:` + una línea por CVE con su parche (`CVE-xxx → actualizar a X.Y.Z` / `parche pendiente` / `sin parche disponible`) |
| `Target` | `Id` | Igual que Hostname |
| `Countermeasure` | — | `Actualizar {pkg} a la última versión vigente para solucionar los CVEs indicados.` |
| `References` | `CVE ID` | URL canónica de NVD del CVE principal: `https://nvd.nist.gov/vuln/detail/{CVE}` |
| `CVSS Base` | `CVSS` | Score numérico o texto según la lógica CVSS de arriba |
| `CVSS Score` | `CVSS` | Mismo valor que `CVSS Base` |

---

## Notas

- **Encoding:** el CSV de salida usa UTF-8 con BOM (`utf-8-sig`) para que Excel
  lo abra correctamente sin problemas de acentos.
- **Separador CSV:** el fichero `.csv` de salida usa `;` (punto y coma), igual
  que la bitácora original, para facilitar el copy-paste sin reconfigurar Excel.
