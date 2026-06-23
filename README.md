# twistlock-export

Convierte el CSV de vulnerabilidades exportado desde **Prisma Cloud (Twistlock)**
al formato de la **Bitácora de Vulnerabilidades corporativa**, generando un
fichero `.xlsx` listo para triaje manual y copy-paste.

---

## Contenido del proyecto

```
twistlock-export/
├── twistlock_export.py          ← script principal
├── requirements.txt             ← dependencia: openpyxl
├── README.md                    ← este fichero
└── CLAUDE.md                    ← notas de arquitectura
```

---

## Requisitos

| Requisito | Versión mínima |
|-----------|----------------|
| Python    | 3.8            |
| openpyxl  | 3.1.0          |

`openpyxl` es la única dependencia externa (genera el `.xlsx`). El resto del
script usa solo la biblioteca estándar (`csv`, `argparse`, `re`, `collections`,
`datetime`, `pathlib`).

### Instalación con entorno virtual (recomendado)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Si PowerShell bloquea la ejecución de scripts:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

---

## Uso

```powershell
python twistlock_export.py -i <ruta_al_csv_de_prisma>
```

**Salida esperada en consola:**

```
Input : <fichero>.csv
Output: <fichero>-export/

Filas en el CSV       : 335
Excluidas (OS)        : 171
Procesadas            : 164
Entradas en bitacora  : 36 (agrupadas por paquete)

  [XLSX] <fichero>.xlsx

Export completado en: <fichero>-export
```

Funciona con los dos scopes de export de Prisma (`registry` e `images`): ver
[Identidad de la imagen](#identidad-de-la-imagen-registry-vs-images).

---

## Flujo de trabajo (importante)

```
1. Ejecutar  ──►  2. TRIAJE MANUAL del .xlsx  ──►  3. Copy-paste a la bitácora
```

### 1. Generar el `.xlsx`

Se crea una carpeta `<nombre_del_csv>-export/` en el mismo directorio del CSV de
entrada, con un único fichero `<nombre_del_csv>.xlsx`: las columnas de la
bitácora en orden, cabeceras coloreadas y texto ajustado. Si la carpeta ya
existe, se reutiliza y el fichero se sobreescribe.

### 2. Triaje manual (antes de pegar)

**El export es un punto de partida, no la verdad absoluta.** Antes de pegar nada
en la bitácora hay que validar cada fila:

- Comprobar que la **versión vulnerable es real y se sufre en el código** (que el
  paquete y la versión detectados se usan de verdad y la vulnerabilidad aplica al
  contexto de la aplicación).
- Si una entrada es un **falso positivo**, se **elimina la fila del `.xlsx`**.

Así, tras el triaje, en el `.xlsx` solo quedan las vulnerabilidades **confirmadas**
(positivos reales).

### 3. Copy-paste a la bitácora

El `.xlsx` replica **las columnas de la bitácora en orden exacto**, desde la
columna **A** hasta la **AH**. Antepone 2 columnas vacías (A y B) para que `ID`
quede en la columna **C**, igual que la bitácora.

1. Copia las filas confirmadas del `.xlsx` (sin la cabecera).
2. Pégalas en la bitácora haciendo clic en la celda de la **columna A** de la
   primera fila libre. Cada valor cae en su columna.
3. **Estira (arrastra) hacia abajo las fórmulas propias de la bitácora** sobre
   las filas recién pegadas. La bitácora se autoajusta y recalcula sus columnas
   con fórmula a partir de los valores copiados.

### Columnas con fórmula de la bitácora

La hoja `Vulnerabilities` **autocalcula 5 columnas**. El export las deja **vacías
a propósito**; al estirar las fórmulas sobre las filas pegadas, se recalculan
solas:

| Col | Campo | Se calcula desde |
|-----|-------|------------------|
| C | ID | nº de fila (`ROW()`) |
| G | COE | IT Development Area |
| N | Severity | CVSS Score |
| P | Category ASVS | ASVS ID |
| R | OWASP Top 10 | ASVS ID |

---

## Lógica de procesamiento

### 1. Filtrado de tipos

Se excluyen todas las filas con `Type = OS` (paquetes del sistema operativo). Se
procesan el resto de tipos (p. ej. `python`, `nuget`, `java`, `Application`),
según lo que contenga la imagen escaneada.

### 2. Agrupación por paquete

Las filas se agrupan por `(imagen, paquete, versión)`. Cada grupo genera **una
sola fila** en la bitácora. Los CVEs del grupo se listan en `Details`,
**deduplicados** y preservando el orden de aparición.

> La deduplicación es necesaria porque Prisma repite el mismo CVE una vez por
> cada ruta de fichero (`Package Path`) donde detecta el paquete.

**Filtro de identificadores:** solo se incluyen `CVE-*`. Los `GHSA-*` y
`PRISMA-*` se descartan.

**Orden de salida:** primero las entradas con score CVSS (de mayor a menor) y,
después, las que no tienen score, ordenadas por severidad. Así una Critical/High
con CVSS=0 no queda enterrada bajo entradas Low.

### 3. Identidad de la imagen (`registry` vs `images`)

El campo `Hostname`/`Target` es la **ruta legible de la imagen**, reconstruida
desde `Registry` + `Repository` + `:` + `Tag` (con fallback al campo `Id` si
faltaran). Esto es necesario porque el campo `Id` no es uniforme entre scopes:

| Scope de export | Valor de `Id` |
|-----------------|---------------|
| `registry`      | ruta completa de la imagen |
| `images`        | digest `sha256:...` |

Reconstruir desde `Registry/Repository:Tag` da una identidad legible y coherente
en ambos formatos.

### 4. Lógica CVSS

Los campos `CVSS Base` y `CVSS Score` corresponden al **CVE principal** del grupo
(mayor severidad; a igualdad, mayor CVSS). El mismo CVE aporta `Threat
Description` y `References`.

| Situación | Valor en bitácora |
|-----------|-------------------|
| CVSS > 0 en Prisma | Score numérico con coma decimal (ej. `8,7`) |
| CVSS = 0 y CVE del año en curso | `Pendiente de valoración NVD/NIST (CVE reciente)` |
| CVSS = 0 y CVE de años anteriores | `Sin puntuación CVSS en NVD` |

> **Nota:** Prisma exporta un único score numérico sin indicar la versión de CVSS
> (2.0 / 3.1 / 4.0) ni el vector. El vector CVSS (que la bitácora usa con CVSS
> 4.0) **no está en el CSV de Prisma** y debe consultarse en NVD si se requiere.

---

## Mapeo de campos

El export genera **todas las columnas de la bitácora** (de `ID` hasta `XX/XX/26`).
Las que no aparecen abajo se generan **vacías**: unas las rellenas a mano y otras
las autocalcula la bitácora con fórmulas (ver "Columnas con fórmula").

| Campo bitácora | Origen | Lógica |
|----------------|--------|--------|
| `ID` | — | Vacío (lo autocalcula la fórmula de la bitácora) |
| `Hostname` | `Registry`/`Repository`/`Tag` | Ruta legible de la imagen (`registro/repo:tag`) |
| `State` | — | Fijo: `Open` |
| `Type` | — | Fijo: `Application` |
| `Vulnerability Title` | `Packages` + `CVE ID` | `Múltiples CVEs en {pkg} ({ver})` o `{CVE} en {pkg} ({ver})` |
| `Severity` | — | **Vacío** (la bitácora lo autocompleta desde el CVSS) |
| `Domain` | — | Fijo: `Configuration Error` |
| `ASVS ID` | — | Fijo: `ASVS-14.2.1` |
| `Threat Description` | `Description` | Descripción del CVE de mayor criticidad del grupo (texto de Prisma) |
| `Details` | `CVE ID` + `Fix Status` | Cabecera + una línea por CVE con su fix (`CVE-xxx → actualizar a X.Y.Z` / `parche pendiente` / `sin parche disponible`) |
| `Target` | `Registry`/`Repository`/`Tag` | Igual que Hostname |
| `Countermeasure` | — | Genérico: `Se recomienda actualizar {pkg} a la última versión disponible del proveedor y revisar las versiones de corrección indicadas en Details.` |
| `References` | `CVE ID` | URL canónica de NVD del CVE principal: `https://nvd.nist.gov/vuln/detail/{CVE}` |
| `CVSS Base` | `CVSS` | Score numérico o texto según la lógica CVSS de arriba |
| `CVSS Score` | `CVSS` | Mismo valor que `CVSS Base` |

---

## Notas

- **Encoding:** el `.xlsx` lo genera `openpyxl`; los textos van en UTF-8 sin
  problemas de acentos.
- **Fichero abierto en Excel:** si el `.xlsx` de salida está abierto, el script
  avisa con un `PermissionError` controlado; ciérralo y reejecuta.
- **Columnas esperadas en el CSV:** ver `CLAUDE.md`.
