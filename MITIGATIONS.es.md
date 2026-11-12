# Mitigaciones

[English](MITIGATIONS.md) | Español

Las mitigaciones para hallazgos de Container, IaC y Secrets aún no están disponibles en la plataforma de
Veracode. Con `--mitigations`, la propia exportación las registra: el repositorio guarda
`veracode-findings.csv` (GitHub lo muestra como tabla), se editan sin conexión en una copia Excel bloqueada y
cada ejecución traslada las mitigaciones a los hallazgos actualizados.

> **Nunca edites `Mitigation Key` ni `Mitigation Status`.** Las escribe el script. La clave asocia cada fila
> con su hallazgo en la siguiente ejecución; si cambia, la mitigación se pierde. En la copia Excel ambas
> están bloqueadas.

## Requisitos

- Todo lo indicado en [README.es.md](README.es.md#requisitos)
- `pip install openpyxl` para la copia Excel

## Inicio rápido

1. Lleva los últimos hallazgos al CSV de seguimiento (se crea en la primera ejecución):

   ```bash
   python veracode_iac_extract.py --compact --mitigations veracode-findings.csv
   ```

   O descarga el artefacto `veracode-findings` de la última ejecución de la [GitHub Action](#github-action) (CSV y Excel).

2. Genera la copia Excel, sin conexión:

   ```bash
   python veracode_iac_extract.py --convert veracode-findings.csv veracode-findings.xlsx
   ```

3. Abre `veracode-findings.xlsx`. En cada fila que quieras mitigar, rellena las celdas amarillas; no se puede editar nada más:

   | Mitigation Type | Mitigation Reason | Mitigation Approved By | Mitigation Expires | Mitigation Notes |
   | --- | --- | --- | --- | --- |
   | accept-risk (lista) | El bucket sirve la página pública de estado a través de CloudFront | lead@acme.com | 2027-11-09 | CHG-4411 |

4. Vuelve a convertirlo en CSV. Esto valida cada mitigación y actualiza `Mitigation Status`:

   ```bash
   python veracode_iac_extract.py --convert veracode-findings.xlsx veracode-findings.csv
   # Wrote 4 rows (1 mitigated finding(s)) to veracode-findings.csv
   ```

5. Haz commit de `veracode-findings.csv` en una pull request. La pull request recibe un comentario así:

   | Change | Finding | Asset | Type | Reason | Approved By | Expires | Notes |
   | --- | --- | --- | --- | --- | --- | --- | --- |
   | Added | AVD-AWS-0086 | acme/payments-infra | by-design | Public status page via CloudFront | lead@acme.com | | CHG-4411 |
   | Changed | AVD-AWS-0089 | acme/sandbox-dev | accept-risk | Sandbox rebuilt nightly | lead@acme.com | ~~2027-02-01~~ 2027-05-01 | |
   | Removed | aws-access-token | acme/payments-infra | false-positive | AWS example key in a test | lead@acme.com | | |

Ejemplo: [examples/veracode-findings.example.csv](examples/veracode-findings.example.csv) (una mitigación,
con todas las columnas rellenas).

## La copia Excel

| Función | Efecto |
| --- | --- |
| Hoja protegida | Solo se pueden editar las celdas Mitigation amarillas. Key, Status y los datos del hallazgo están bloqueados. Se puede seguir filtrando |
| Mitigation Type | Lista desplegable con los cinco tipos; rechaza otros valores |
| Mitigation Expires | Solo acepta fechas; se muestran como `AAAA-MM-DD` |
| Notas en el encabezado y avisos en las celdas | Explican cada columna Mitigation al seleccionarla |
| Hoja How to use | Pasos, una fila de ejemplo, tipos y estados |
| Formato | Colores por estado y severidad, encabezado fijo, filtros, Veracode Link con enlace, se imprime en una página de ancho |

La protección no tiene contraseña. Evita errores, no cambios intencionados (Revisar > Desproteger hoja).
No hagas commit del `.xlsx`; está en `.gitignore`.

## Uso

```bash
# Actualizar el CSV de seguimiento desde Veracode (lo lee y lo vuelve a escribir)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv

# CSV -> Excel y vuelta, sin conexión
python veracode_iac_extract.py --convert veracode-findings.csv veracode-findings.xlsx
python veracode_iac_extract.py --convert veracode-findings.xlsx veracode-findings.csv

# Validar y listar todas las mitigaciones, sin conexión
python veracode_iac_extract.py --check-mitigations veracode-findings.csv

# Qué cambió respecto a otra versión (Markdown, como en el comentario de la pull request)
python veracode_iac_extract.py --check-mitigations veracode-findings.csv --against old.csv

# Solo lo que falta por corregir, en otro archivo (el de seguimiento no cambia)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv \
  --where "Mitigation Status!=Mitigated" -o to-fix.xlsx
```

## Configuración

### Flags

| Flag | Efecto |
| --- | --- |
| `--mitigations ARCHIVO` | Lee las mitigaciones de `ARCHIVO` (`.csv` o `.xlsx`) y vuelve a escribir la exportación en él. Con `-o` se escribe en otro archivo |
| `--convert ENTRADA SALIDA` | Convierte entre `.csv` y `.xlsx`, sin conexión. Valida las mitigaciones y actualiza Mitigation Status; no escribe nada si no son válidas |
| `--check-mitigations ARCHIVO` | Valida y lista todas las mitigaciones, sin conexión: sale con 0 si es válido, 2 si no |
| `--against BASE` | Con `--check-mitigations`: tabla Markdown de las mitigaciones añadidas, cambiadas o eliminadas respecto a `BASE` |

### Columnas añadidas

| Columna | La rellena | Notas |
| --- | --- | --- |
| Mitigation Status | El script | Primera columna. No la edites |
| Mitigation Type | Tú | Uno de los tipos de abajo |
| Mitigation Reason | Tú | Obligatoria |
| Mitigation Approved By | Tú | Obligatoria |
| Mitigation Expires | Tú | `AAAA-MM-DD`. Obligatoria para `accept-risk` |
| Mitigation Notes | Tú | Opcional (ticket, número de cambio) |
| Mitigation Key | El script | Última columna. No la edites |

### Tipos (los mismos que en Static Analysis)

| Tipo | Cuándo usarlo | Nombre en Static Analysis |
| --- | --- | --- |
| `false-positive` | El hallazgo no es real | Potential False Positive |
| `by-design` | La configuración es intencionada y está aprobada | Mitigate by Design |
| `network-environment` | Un control de red lo bloquea (WAF, security group, red privada) | Mitigate by Network Environment |
| `os-environment` | El sistema operativo o el runtime lo bloquea (host bastionado, sistema de archivos de solo lectura, sin shell) | Mitigate by OS Environment |
| `accept-risk` | El negocio acepta el riesgo; requiere Mitigation Expires | Accept the Risk |

### Estados

| Mitigation Status | Significado |
| --- | --- |
| Open | No mitigado |
| Mitigated | Mitigado y no caducado |
| Expired | Ha pasado Mitigation Expires; cuenta como abierto |
| Not in export | Mitigado, pero el hallazgo no estaba en la última exportación (corregido o filtrado). Se conserva para que la mitigación vuelva si el hallazgo vuelve. Borra la fila cuando ya no haga falta |

## GitHub Action

[.github/workflows/veracode-iac-findings.yml](.github/workflows/veracode-iac-findings.yml):

| Disparador | Job | Resultado |
| --- | --- | --- |
| Diario, 04:23 UTC, o Actions > Veracode IaC findings > Run workflow | `export` | Actualiza `veracode-findings.csv` a partir de la copia del repositorio y lo adjunta, junto con la copia Excel, como artefacto `veracode-findings` |
| Pull request que cambia `veracode-findings.csv` | `check-mitigations` | Comenta la tabla de cambios en la pull request (se actualiza en cada push), la añade al resumen del job y falla si alguna mitigación no es válida |

La Action no hace commit. Haz commit del CSV tú mismo mediante una pull request.

Configuración:

1. Añade los secretos del repositorio `VERACODE_API_KEY_ID` y `VERACODE_API_KEY_SECRET`.
2. Opcional: exige el check `check-mitigations` antes de fusionar.
3. Opcional: variable de repositorio `VERACODE_EXTRACT_ARGS` con filtros para todas las ejecuciones, por ejemplo `--asset my-org/*`.

Las pull requests desde forks reciben un token de solo lectura: tienen el resumen del job, pero no el comentario.

## Notas importantes

- **La herramienta no controla la aprobación.** `Mitigation Approved By` es texto libre; quien pueda cambiar el CSV puede mitigar cualquier cosa. Decide cómo se controlan las aprobaciones, por ejemplo con una entrada de CODEOWNERS para `veracode-findings.csv` y una protección de rama que exija esa revisión.
- **Usa `--compact` para el archivo que subes al repositorio.** La exportación completa incluye `Code Lines`, que puede contener el propio secreto.
- **Las mitigaciones no cambian nada en la plataforma de Veracode**, tampoco el resultado de las políticas.
- `Mitigation Key` ignora los números de línea y las etiquetas de imagen (`app:1.2` y `app:1.3` comparten claves). Cambia si el archivo se mueve o se renombra, si se renombra el recurso o si cambia el valor de un secreto: la fila antigua pasa a `Not in export` y el hallazgo aparece como una fila nueva `Open`. Copia las columnas Mitigation a la fila nueva.
- Las filas con la misma clave (por ejemplo, la misma imagen con dos etiquetas) comparten una mitigación; basta con rellenar una.
- Usa los mismos filtros en cada ejecución. Los hallazgos abiertos que excluya un filtro desaparecen del archivo; los mitigados se conservan como `Not in export`.
- Si las columnas Mitigation no son válidas, `--mitigations` y `--convert` se detienen con el código de salida 2 y no cambian los archivos.
- El CSV también se puede editar directamente en Excel. Se leen bien los archivos guardados con separador `;` o codificación de Windows, y las fechas reescritas (por ejemplo `31/12/2027`) se aceptan si no son ambiguas.
- El resumen de la ejecución lista las mitigaciones caducadas y las que caducan en los próximos 30 días.

## Solución de problemas

| Mensaje | Solución |
| --- | --- |
| `Nothing was changed. Fix veracode-findings.csv and run again.` / `Nothing was written.` | Ejecuta `--check-mitigations`; lista cada problema por número de fila |
| `Excel files need openpyxl` | `pip install openpyxl` |
| `Mitigation Key is missing or changed. Do not edit it` | Recupera la clave del archivo anterior o rehaz la fila desde una exportación nueva |
| `has no Mitigation Key column` | El archivo no se escribió con `--mitigations`; ejecuta el paso 1 del inicio rápido |
| `same Mitigation Key as row N but a different mitigation` | Haz que ambas filas coincidan o vacía una |
| `could be day/month or month/day. Use YYYY-MM-DD` | El CSV se editó directamente; escribe la fecha como `AAAA-MM-DD` o edítalo con la copia Excel |
