# Mitigaciones

[English](MITIGATIONS.md) | Español

Las mitigaciones para hallazgos de Container, IaC y Secrets aún no están disponibles en la plataforma de
Veracode. Con `--mitigations`, el CSV de la exportación es también donde se registran las mitigaciones:
rellenas las columnas Mitigation y la siguiente ejecución las traslada a los hallazgos actualizados. Un solo
archivo, guardado en este repositorio.

## Requisitos

Los mismos que en [README.es.md](README.es.md#requisitos). Sin paquetes adicionales.

## Inicio rápido

1. Exporta al archivo de seguimiento (se crea en la primera ejecución, con todos los hallazgos `Open`):

   ```bash
   python veracode_iac_extract.py --compact --mitigations veracode-findings.csv
   ```

2. Abre `veracode-findings.csv` en Excel. En cada fila que quieras mitigar, rellena:

   | Mitigation Type | Mitigation Reason | Mitigation Approved By | Mitigation Expires | Mitigation Notes |
   | --- | --- | --- | --- | --- |
   | by-design | Página pública de estado vía CloudFront | lead@acme.com | | CHG-4411 |
   | accept-risk | Sandbox que se recrea cada noche | lead@acme.com | 2027-02-01 | |

   Guárdalo como CSV. No edites `Mitigation Key`. Consulta
   [examples/veracode-findings.example.csv](examples/veracode-findings.example.csv) para ver un archivo con
   un hallazgo mitigado.

3. Valida y haz commit del archivo mediante una pull request:

   ```bash
   python veracode_iac_extract.py --check-mitigations veracode-findings.csv
   # veracode-findings.csv: 2 mitigated finding(s), all valid.
   ```

4. Repite el paso 1. El archivo se reescribe con los últimos hallazgos y las mitigaciones trasladadas:

   ```text
     Mitigation status  : Open 2, Mitigated 1, Expired 0, Not in export 1
   ```

## Uso

```bash
# Actualizar el archivo de seguimiento (lo lee y lo vuelve a escribir)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv

# Solo lo que falta por corregir, en otro archivo (el de seguimiento no cambia)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv \
  --where "Mitigation Status!=Mitigated" -o to-fix.csv

# Validar las columnas Mitigation (sin acceso a Veracode)
python veracode_iac_extract.py --check-mitigations veracode-findings.csv
```

## Configuración

### Flags

| Flag | Efecto |
| --- | --- |
| `--mitigations ARCHIVO.csv` | Lee las mitigaciones del archivo y vuelve a escribir la exportación en él. Con `-o` se escribe en otro archivo |
| `--check-mitigations ARCHIVO.csv` | Valida las columnas Mitigation y termina: 0 válido, 2 no válido |

### Columnas añadidas

| Columna | La rellena | Notas |
| --- | --- | --- |
| Mitigation Status | El script | Primera columna. Ver abajo |
| Mitigation Type | Tú | Uno de los tipos de abajo |
| Mitigation Reason | Tú | Obligatoria |
| Mitigation Approved By | Tú | Obligatoria |
| Mitigation Expires | Tú | `AAAA-MM-DD`. Obligatoria para `accept-risk` |
| Mitigation Notes | Tú | Opcional (ticket, número de cambio) |
| Mitigation Key | El script | Asocia la fila con el hallazgo en la siguiente ejecución. No la edites |

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
| Not in export | Mitigado, pero el hallazgo no está en esta exportación (corregido o filtrado). Se conserva para que la mitigación vuelva si el hallazgo vuelve. Borra la fila cuando ya no haga falta |

## GitHub Action

[.github/workflows/veracode-iac-findings.yml](.github/workflows/veracode-iac-findings.yml):

| Disparador | Job | Resultado |
| --- | --- | --- |
| Diario, 04:23 UTC, o Actions > Veracode IaC findings > Run workflow | `export` | Lee `veracode-findings.csv` del repositorio y adjunta el archivo actualizado como artefacto `veracode-findings` |
| Pull request que cambia `veracode-findings.csv` | `check-mitigations` | Falla si las columnas Mitigation no son válidas |

La Action no hace commit. Para mitigar: descarga el artefacto, rellena las columnas Mitigation y haz commit
como `veracode-findings.csv` mediante una pull request.

Configuración:

1. Añade los secretos del repositorio `VERACODE_API_KEY_ID` y `VERACODE_API_KEY_SECRET`.
2. Opcional: exige el check `check-mitigations` antes de fusionar.
3. Opcional: variable de repositorio `VERACODE_EXTRACT_ARGS` con filtros para todas las ejecuciones, por ejemplo `--asset my-org/*`.

## Notas importantes

- **La herramienta no controla la aprobación.** `Mitigation Approved By` es texto libre; quien pueda cambiar el archivo puede mitigar cualquier cosa. Decide cómo se controlan las aprobaciones, por ejemplo con una entrada de CODEOWNERS para `veracode-findings.csv` y una protección de rama que exija esa revisión.
- **Usa `--compact` para un archivo que vayas a subir al repositorio.** La exportación completa incluye `Code Lines`, que puede contener el propio secreto.
- **Las mitigaciones no cambian nada en la plataforma de Veracode**, tampoco el resultado de las políticas.
- `Mitigation Key` ignora los números de línea y las etiquetas de imagen (`app:1.2` y `app:1.3` comparten claves). Cambia si el archivo se mueve o se renombra, si se renombra el recurso o si cambia el valor de un secreto: la fila antigua pasa a `Not in export` y el hallazgo aparece como una fila nueva `Open`. Copia las columnas Mitigation a la fila nueva.
- Las filas con la misma clave (por ejemplo, la misma imagen con dos etiquetas) comparten una mitigación; basta con rellenar una.
- Usa los mismos filtros en cada ejecución. Los hallazgos abiertos que excluya un filtro desaparecen del archivo; los mitigados se conservan como `Not in export`.
- Si las columnas Mitigation no son válidas, la ejecución se detiene con el código de salida 2 y el archivo no cambia.
- Se leen bien los archivos que Excel guarda con separador `;` o codificación de Windows. Las fechas que Excel reescribe (por ejemplo `31/12/2027`) se aceptan si no son ambiguas; si no, usa `AAAA-MM-DD`.
- El resumen de la ejecución lista las mitigaciones caducadas y las que caducan en los próximos 30 días.

## Solución de problemas

| Mensaje | Solución |
| --- | --- |
| `Nothing was changed. Fix veracode-findings.csv and run again.` | Ejecuta `--check-mitigations`; lista cada problema por número de línea |
| `could be day/month or month/day. Use YYYY-MM-DD` | Escribe la fecha como `AAAA-MM-DD` (en Excel, da formato de texto a la columna) |
| `Mitigation Key is missing or changed. Do not edit it` | Recupera la clave del archivo anterior o rehaz la fila desde una exportación nueva |
| `has no Mitigation Key column` | El archivo no se escribió con `--mitigations`; ejecuta el paso 1 para crearlo |
| `same Mitigation Key as line N but a different mitigation` | Haz que ambas filas coincidan o vacía una |
