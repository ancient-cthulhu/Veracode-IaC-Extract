# Mitigaciones

[English](MITIGATIONS.md) | Español

Las mitigaciones para hallazgos de Container, IaC y Secrets aún no están disponibles en la plataforma de
Veracode. Con `--mitigations`, la propia exportación es donde se registran las mitigaciones: rellenas las
columnas Mitigation y la siguiente ejecución las traslada a los hallazgos actualizados. Un solo archivo,
guardado en este repositorio.

> **Nunca edites `Mitigation Key` ni `Mitigation Status`.** Las escribe el script. La clave asocia cada fila
> con su hallazgo en la siguiente ejecución; si cambia, la mitigación se pierde. En el Excel ambas están
> bloqueadas.

## Requisitos

- Todo lo indicado en [README.es.md](README.es.md#requisitos)
- `pip install openpyxl` para `.xlsx` (recomendado). `.csv` no necesita nada más.

## Inicio rápido

1. Crea el libro de seguimiento (todos los hallazgos empiezan como `Open`):

   ```bash
   python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx
   ```

2. Abre `veracode-findings.xlsx`. En cada fila que quieras mitigar, rellena las columnas amarillas; no se
   puede editar nada más:

   | Mitigation Type | Mitigation Reason | Mitigation Approved By | Mitigation Expires | Mitigation Notes |
   | --- | --- | --- | --- | --- |
   | accept-risk (lista) | El bucket sirve la página pública de estado a través de CloudFront | lead@acme.com | 2027-11-09 | CHG-4411 |

   Consulta [examples/veracode-findings.example.xlsx](examples/veracode-findings.example.xlsx).

3. Valida y haz commit del archivo mediante una pull request:

   ```bash
   python veracode_iac_extract.py --check-mitigations veracode-findings.xlsx
   ```

   ```text
   OK     row 2 (AVD-AWS-0086) acme/payments-infra: accept-risk, approved by lead@acme.com, expires 2027-11-09, notes: CHG-4411. Bucket serves the public status page through CloudFront
   veracode-findings.xlsx: 1 mitigated finding(s), all valid.
   ```

4. Repite el paso 1. El archivo se reescribe con los últimos hallazgos y las mitigaciones trasladadas:

   ```text
     Mitigation status  : Open 3, Mitigated 1, Expired 0, Not in export 0
   ```

## El archivo Excel

| Función | Efecto |
| --- | --- |
| Hoja protegida | Solo se pueden editar las celdas Mitigation amarillas. Key, Status y los datos del hallazgo están bloqueados. Se puede seguir filtrando |
| Mitigation Type | Lista desplegable con los cinco tipos; rechaza otros valores |
| Mitigation Expires | Solo acepta fechas; se muestran como `AAAA-MM-DD` |
| Notas en el encabezado y avisos en las celdas | Explican cada columna Mitigation al seleccionarla |
| Hoja How to use | Pasos, una fila de ejemplo, tipos y estados |
| Formato | Colores por estado y severidad, encabezado fijo, filtros, Veracode Link con enlace, se imprime en una página de ancho |

La protección no tiene contraseña. Evita errores, no cambios intencionados (Revisar > Desproteger hoja).

## Uso

```bash
# Actualizar el archivo de seguimiento (lo lee y lo vuelve a escribir)
python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx

# Solo lo que falta por corregir, en otro archivo (el de seguimiento no cambia)
python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx \
  --where "Mitigation Status!=Mitigated" -o to-fix.xlsx

# Validar y listar todas las mitigaciones (sin acceso a Veracode)
python veracode_iac_extract.py --check-mitigations veracode-findings.xlsx
```

`.csv` funciona igual (`--mitigations veracode-findings.csv`), sin las funciones de Excel.

## Configuración

### Flags

| Flag | Efecto |
| --- | --- |
| `--mitigations ARCHIVO` | `.xlsx` o `.csv`. Lee las mitigaciones del archivo y vuelve a escribir la exportación en él. Con `-o` se escribe en otro archivo |
| `--check-mitigations ARCHIVO` | Valida las columnas Mitigation, lista todas las mitigaciones y termina: 0 válido, 2 no válido |

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
| Not in export | Mitigado, pero el hallazgo no está en esta exportación (corregido o filtrado). Se conserva para que la mitigación vuelva si el hallazgo vuelve. Borra la fila cuando ya no haga falta |

## GitHub Action

[.github/workflows/veracode-iac-findings.yml](.github/workflows/veracode-iac-findings.yml):

| Disparador | Job | Resultado |
| --- | --- | --- |
| Diario, 04:23 UTC, o Actions > Veracode IaC findings > Run workflow | `export` | Lee `veracode-findings.xlsx` del repositorio y adjunta el archivo actualizado como artefacto `veracode-findings` |
| Pull request que cambia `veracode-findings.xlsx` | `check-mitigations` | Falla si las columnas Mitigation no son válidas; su log lista todas las mitigaciones para quien revisa |

La Action no hace commit. Para mitigar: descarga el artefacto, rellena las columnas amarillas y haz commit
como `veracode-findings.xlsx` mediante una pull request.

Configuración:

1. Añade los secretos del repositorio `VERACODE_API_KEY_ID` y `VERACODE_API_KEY_SECRET`.
2. Opcional: exige el check `check-mitigations` antes de fusionar.
3. Opcional: variable de repositorio `VERACODE_EXTRACT_ARGS` con filtros para todas las ejecuciones, por ejemplo `--asset my-org/*`.

## Notas importantes

- **La herramienta no controla la aprobación.** `Mitigation Approved By` es texto libre; quien pueda cambiar el archivo puede mitigar cualquier cosa. Decide cómo se controlan las aprobaciones, por ejemplo con una entrada de CODEOWNERS para el archivo de seguimiento y una protección de rama que exija esa revisión.
- **Los diffs de archivos `.xlsx` en una pull request no se pueden leer.** Quien revisa lee el log de `check-mitigations`. Usa `.csv` si quieres diffs línea a línea.
- **Usa `--compact` para un archivo que vayas a subir al repositorio.** La exportación completa incluye `Code Lines`, que puede contener el propio secreto.
- **Las mitigaciones no cambian nada en la plataforma de Veracode**, tampoco el resultado de las políticas.
- `Mitigation Key` ignora los números de línea y las etiquetas de imagen (`app:1.2` y `app:1.3` comparten claves). Cambia si el archivo se mueve o se renombra, si se renombra el recurso o si cambia el valor de un secreto: la fila antigua pasa a `Not in export` y el hallazgo aparece como una fila nueva `Open`. Copia las columnas Mitigation a la fila nueva.
- Las filas con la misma clave (por ejemplo, la misma imagen con dos etiquetas) comparten una mitigación; basta con rellenar una.
- Usa los mismos filtros en cada ejecución. Los hallazgos abiertos que excluya un filtro desaparecen del archivo; los mitigados se conservan como `Not in export`.
- Si las columnas Mitigation no son válidas, la ejecución se detiene con el código de salida 2 y el archivo no cambia.
- Se leen bien los CSV que Excel guarda con separador `;` o codificación de Windows. Las fechas reescritas (por ejemplo `31/12/2027`) se aceptan si no son ambiguas.
- El resumen de la ejecución lista las mitigaciones caducadas y las que caducan en los próximos 30 días.

## Solución de problemas

| Mensaje | Solución |
| --- | --- |
| `Nothing was changed. Fix veracode-findings.xlsx and run again.` | Ejecuta `--check-mitigations`; lista cada problema por número de fila |
| `Excel files need openpyxl` | `pip install openpyxl` |
| `Mitigation Key is missing or changed. Do not edit it` | Recupera la clave del archivo anterior o rehaz la fila desde una exportación nueva |
| `has no Mitigation Key column` | El archivo no se escribió con `--mitigations`; ejecuta el paso 1 para crearlo |
| `same Mitigation Key as row N but a different mitigation` | Haz que ambas filas coincidan o vacía una |
| `could be day/month or month/day. Use YYYY-MM-DD` | Solo CSV: escribe la fecha como `AAAA-MM-DD` |
