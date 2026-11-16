# Extracción de hallazgos de Veracode IaC / Container / Secrets

[English](../../README.md) | Español

Exporta los hallazgos de Veracode Container Security (imágenes de contenedor, IaC, secretos) a CSV, JSON,
JSONL o Excel, una fila por hallazgo, con filtros.

Para seguir los hallazgos a lo largo del tiempo y aprobar mitigaciones, consulta [Veracode-IaC-Mitigation-Tracker](https://github.com/ancient-cthulhu/Veracode-IaC-Mitigation-Tracker).

## Requisitos

- Python 3.9 o posterior
- `pip install -r requirements.txt` (requests, veracode-api-signing, veracode-api-py; openpyxl para la salida en Excel `.xlsx`)
- Credenciales de la API de Veracode en `~/.veracode/credentials`, o en las variables de entorno `VERACODE_API_ID` y
  `VERACODE_API_KEY` (también se aceptan `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET`)
- Cuenta con rol Reviewer que pueda ver los escaneos de Container e IaC

## Inicio rápido

```bash
python veracode_iac_extract.py                # último escaneo de cada asset -> veracode_iac_findings.csv
python veracode_iac_extract.py --compact      # vista de 14 columnas para desarrolladores
python veracode_iac_extract.py --list-scans   # solo el inventario de escaneos, sin hallazgos
python veracode_iac_extract.py --all-scans    # todos los escaneos del historial, una fila por hallazgo y escaneo
```

Cada ejecución termina con un resumen: escaneos consultados, hallazgos exportados, recuentos por severidad y
tipo, y las peticiones que fallaron.

## Uso

```bash
# Repositorios y organizaciones
python veracode_iac_extract.py --asset "my-org/payments-api"
python veracode_iac_extract.py --asset "my-org/*" --exclude-asset "sandbox,archived"

# Tipo de escaneo y de asset
python veracode_iac_extract.py --scan-type container
python veracode_iac_extract.py --asset-type image --asset "registry.acme.com/*"

# Qué corregir primero
python veracode_iac_extract.py --severity high+ --fixable --compact

# Tipos de hallazgo
python veracode_iac_extract.py --type misconfiguration --file "*.tf"
python veracode_iac_extract.py --type secret --since 30d

# ¿Nos afecta?
python veracode_iac_extract.py --id CVE-2024-3094
python veracode_iac_extract.py --library "log4j*" --severity critical,high

# Políticas, actividad, informes
python veracode_iac_extract.py --policy failed --list-scans -o failed_scans.csv
python veracode_iac_extract.py --all-scans --since 2026-09-01 --until 2026-09-30
python veracode_iac_extract.py --scanned-by ci_pipeline_user
python veracode_iac_extract.py --summary-csv per_asset.csv

# Cualquier columna de la salida
python veracode_iac_extract.py --where "Scan Policy Status!=passed" --where "Provider=AWS"
```

### Reglas de coincidencia (todos los filtros de texto)

| Valor | Coincide con |
| --- | --- |
| `payments` | Contiene "payments" |
| `my-org/*` | Comodín sobre el valor completo (`*` cualquier texto, `?` un carácter) |
| `a,b` | a o b |
| `re:^prod-` | Expresión regular |

Nunca distingue mayúsculas de minúsculas. Varios flags se combinan con Y.

### Filtros de escaneo (antes de pedir hallazgos)

| Flag | Valores |
| --- | --- |
| `--asset`, `--exclude-asset` | Nombre del asset, ID del asset u origen |
| `--scan-type` | `container`, `iac` |
| `--asset-type` | `image`, `repo`, `archive`, `directory` |
| `--policy` | `failed`, `passed`, `not-assessed` |
| `--scanned-by` | Usuario que lanzó el escaneo |
| `--since`, `--until` | `AAAA-MM-DD`, `AAAAMMDD`, fecha y hora ISO, o relativo: `12h`, `30d`, `2w`. Con una fecha sola, `--until` incluye ese día |
| `--all-scans` | Todos los escaneos del historial en lugar de solo el último de cada asset (por defecto) |
| `--latest-only` | Solo el último escaneo de cada asset. Es lo predeterminado; se mantiene por compatibilidad |
| `--track-history` | Consulta todos los escaneos para rellenar First Seen, Last Seen y Seen In Scans; exporta solo el último escaneo de cada asset |
| `--scan-id` | Un escaneo concreto, sea el último o no |

### Filtros de hallazgo (después de la descarga)

| Flag | Valores |
| --- | --- |
| `--severity` | `high+` (ese nivel y superiores) o una lista: `critical,high` |
| `--type` (`--finding-type`) | `vulnerability`, `misconfiguration`, `secret` |
| `--id` (`--cve`, `--finding-id`) | CVE o ID del hallazgo. Un ID simple coincide exactamente (`CVE-2024-3094`, no `CVE-2024-30940`); comodines, `re:` y listas con comas siguen las reglas de coincidencia |
| `--library` | Nombre o `nombre@versión` |
| `--file` | Ruta del archivo |
| `--rule`, `--category` | ID de la regla, categoría del hallazgo |
| `--fixable` | Solo hallazgos con corrección disponible |
| `--cvss N` (`--min-cvss`) | CVSS de N o más |
| `--search` (`--grep`) | Texto libre o regex en título, descripción, corrección, IDs, librería, categoría, recurso y ruta |
| `--where "COL=texto"` | Cualquier columna de la salida. `!=` excluye. Repetible |

### Salida

| Flag | Efecto |
| --- | --- |
| `-o ARCHIVO` | Archivo de salida (por defecto `veracode_iac_findings.csv`). La extensión fija el formato: `.csv`, `.json`, `.jsonl`, `.xlsx` |
| `--format` | Fuerza `csv`, `json`, `jsonl` o `xlsx` sin importar la extensión |
| `--compact` | Asset Name, Scan Type (`container`, `iac`), Asset Type (`image`, `repo`, `archive`, `directory`), Severity, CVSS, Finding Type, Finding ID, Title, Library, Fixed Versions, Location, Suggested Fix, Scan Date, Veracode Link |
| `--columns "A,B,C"` | Elige y ordena las columnas. Un nombre desconocido detiene la ejecución antes de cualquier petición (código 2) |
| `--summary-csv ARCHIVO` | Resumen por asset (Asset Name, Asset ID): escaneos, hallazgos, corregibles, recuentos por severidad y tipo |
| `--list-scans` | Solo el inventario de escaneos |
| `--match-apps` | Añade Application Name, Application GUID, Business Unit y Teams cuando el nombre del asset coincide con un perfil de aplicación |
| `--keep-empty-columns` | Mantiene las columnas vacías en toda la exportación (por defecto se omiten) |
| `--no-extra-columns` | Omite las columnas `Scan: <campo>` / `Finding: <campo>` |
| `--no-csv-safe` | No antepone `'` a las celdas que empiezan por `=`, `+`, `-`, `@` |

### Columnas (exportación completa)

Los nombres de columna salen en inglés.

| Grupo | Columnas |
| --- | --- |
| Qué es | Severity, Severity Rank (5 critical a 0 unknown), CVSS, Exploitability Score, Impact Score, Finding Type, Finding ID, CVE ID, Rule ID, Category, Title, Description, References, Finding Policy Status |
| Dónde está | Asset Name, Asset ID, Asset Type, Scan Type, Scan Source, Location (`ruta:línea` o `ruta:inicio-fin`), File Path, Start Line, End Line, All File Paths, Code Lines, Provider, Service, Resource, Image Tags, Image Distro, Image Hash, Image Labels, Layer IDs |
| Corrección | Library (`nombre@versión`), Library Name, Library Version, Fix Available (vacío si no hay librería), Fix State, Fixed Versions, Suggested Fix |
| Escaneo | Scan ID, Scan Date, Scan Age Days, Scan Duration, Scan Status, Scanned By, Policy Name, Policy ID, Scan Policy Status, Scan Total Findings, Scan Critical/High/Medium/Low/Negligible/Unknown, Veracode Link |
| Historial | Finding Key, Is Latest Scan For Asset, First Seen, Last Seen, Seen In Scans |

Los campos de la API que no aparecen arriba se incluyen como columnas `Scan: <campo>` o `Finding: <campo>`.

La salida en Excel (`.xlsx`) tiene el encabezado fijo y con filtros, colores por severidad, Veracode Link con
enlace, y se imprime en una página de ancho. Las celdas siempre son texto, nunca fórmulas. `--list-scans`
escribe una hoja `Scans`. Una exportación que supera el límite de Excel de 1.048.575 filas termina con código 2
sin escribir nada; usa CSV en ese caso.

## Configuración

| Ajuste | Por defecto | Para qué |
| --- | --- | --- |
| `--base-url` / `VERACODE_IAC_BASE_URL` | Según la región de las credenciales (comercial de EE. UU. o UE) | API de consulta de escaneos de contenedor. Obligatorio en FedRAMP |
| `--link-base` / `VERACODE_IAC_LINK_BASE` | Según la región de las credenciales | Base de la columna Veracode Link |
| `--api-base` / `VERACODE_API_BASE` | Según la región de las credenciales | API REST que usa `--match-apps` |
| `--ca-cert ARCHIVO` | CAs del sistema | Bundle de CA corporativo (inspección SSL) |
| `--rps` | 2 | Máximo de peticiones por segundo, compartido por todos los workers |
| `--max-workers` | 4 | Peticiones simultáneas |
| `--max-attempts` | 6 | Intentos por petición |
| `--timeout` | 90 | Segundos por petición |
| `--no-server-search` | desactivado | Filtra `--asset` en local en lugar de con la búsqueda de la API |
| `--fetch-empty-scans` | desactivado | Consulta también los escaneos cuyos totales no muestran hallazgos coincidentes |
| `--ignore-failures` | desactivado | Sale con 0 y sustituye la salida aunque fallen algunas peticiones |

## Notas importantes

- `--asset` se filtra en el servidor; los filtros de escaneo se aplican antes de pedir hallazgos. Los filtros de hallazgo, después de la descarga.
- Se omiten los escaneos cuyos totales por severidad no pueden coincidir: con `--severity critical`, nunca se consulta un escaneo sin critical. `--fetch-empty-scans` lo desactiva.
- Ante un HTTP 429 todos los workers se pausan y se respeta `Retry-After` (hasta 90 segundos).
- `Finding Key` (`mk-` y 12 caracteres hexadecimales) ignora los números de línea y las etiquetas de imagen (`app:1.2` y `app:1.3` comparten claves). Cambia si el archivo se mueve o se renombra, si se renombra el recurso, o si cambia el valor de un secreto.
- **Por defecto solo se exporta el último escaneo de cada asset.** `--since` / `--until` mantienen entonces los últimos escaneos dentro de ese periodo; añade `--all-scans` para todos los escaneos de un periodo. `--latest-only` se sigue aceptando y no cambia nada.
- First Seen / Last Seen / Seen In Scans solo cubren los escaneos obtenidos en esa ejecución.
- El archivo de salida solo se sustituye cuando la ejecución termina. Si fallan algunas peticiones, se conserva el archivo anterior y la exportación parcial va a `<nombre>.partial.<ext>` (código 1); `--ignore-failures` escribe la salida de todos modos.
- Si el archivo de salida está abierto en otro programa (Excel), se reintenta un momento y después se escribe `<nombre>.<AAAAmmdd-HHMMSS>.<ext>` a su lado, con código 1.

## Códigos de salida

| Código | Significado |
| --- | --- |
| 0 | Completado |
| 1 | Incompleto: fallaron algunas peticiones (aparecen en el resumen), o el archivo de salida estaba bloqueado |
| 2 | Argumentos incorrectos |
| 130 | Interrumpido |

## API de librería

Otros scripts pueden importar el archivo en lugar de ejecutarlo. Los nombres admitidos son los de `__all__`;
`__version__` es la versión publicada.

```python
import veracode_iac_extract as vx

scans, rows, failures = vx.collect_latest(asset="my-org/*", scan_type="iac")
```

```python
collect_latest(base_url=None, link_base=None, *, asset=None, exclude_asset=None, scan_type=None,
               asset_type=None, scanned_by=None, policy=None, since=None, until=None, workers=4, rps=2.0,
               max_attempts=6, timeout=90, ca_cert=None, minter=None, now=None, log=print)
```

Lee todos los hallazgos del último escaneo de cada asset que pasa los filtros de escaneo. Los argumentos de filtro
aceptan los mismos valores que los flags (un patrón o una lista de patrones). No se omite ningún escaneo y no se
escribe nada.

| Devuelve | Contenido |
| --- | --- |
| `scans` | Una fila por escaneo del tenant, con las columnas de escaneo de la exportación. `"_read": True` en los escaneos cuyos hallazgos se leyeron completos |
| `rows` | Una fila por hallazgo de esos escaneos, con las columnas de la exportación (Code Lines incluida) |
| `failures` | `(scope, detail)` de cada petición fallida. Si no está vacío, los datos están incompletos |

Lanza `ExtractError`: `exit_code` 2 si la entrada es incorrecta, 1 si no se puede leer el token o la lista de
escaneos. `base_url` y `link_base` salen de la región de las credenciales si no se indican (obligatorios en
FedRAMP).

## Solución de problemas

| Síntoma | Solución |
| --- | --- |
| Error de autenticación al empezar | Revisa las credenciales, el rol Reviewer y el acceso a los escaneos de Container/IaC |
| Errores de TLS o de certificado | `--ca-cert corp.pem` |
| Tenant FedRAMP | `--base-url` (o `VERACODE_IAC_BASE_URL`), `--link-base`, y `--api-base` con `--match-apps` |
| Un filtro no devuelve nada | Repite con `--no-server-search` y compara el valor con la salida de `--list-scans` |
| `refers to a column that never appeared` | La columna de `--where` no existe en esta exportación; revisa los nombres de columna de arriba |

## Documentación relacionada

- [Veracode-IaC-Mitigation-Tracker](https://github.com/ancient-cthulhu/Veracode-IaC-Mitigation-Tracker): seguimiento de hallazgos con mitigaciones, basado en este script
