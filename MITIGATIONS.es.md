# Mitigaciones

[English](MITIGATIONS.md) | Español

Las mitigaciones para hallazgos de Container, IaC y Secrets no están disponibles en la plataforma de Veracode.
El seguimiento de hallazgos (consulta [README.es.md](README.es.md#seguimiento-de-hallazgos-recomendado))
guarda las aprobadas en `mitigations.yml` y las muestra en `FINDINGS.md`, `tracking/findings.csv` y las
exportaciones.

## Solicitar y aprobar

1. **Solicitar.** En `FINDINGS.md`, pulsa **Mitigate** en el hallazgo. GitHub abre el formulario de incidencia
   *Mitigation request* con Finding Key, Finding ID y Asset ya rellenos. Elige el tipo, escribe el motivo, añade
   la fecha de caducidad para `accept-risk` y envíalo. También puedes abrir el formulario desde Issues > New issue
   y copiar la Finding Key de `tracking/findings.csv`.
2. **Aprobar.** Un aprobador revisa la incidencia y añade la etiqueta `approved`. Los aprobadores son los logins
   de GitHub de la variable de repositorio `MITIGATION_APPROVERS` (Settings > Secrets and variables > Actions >
   Variables), separados por comas o espacios.
3. **Registrada.** [veracode-mitigation.yml](.github/workflows/veracode-mitigation.yml) comprueba el aprobador y
   el formulario, añade la siguiente entrada (`M-0001`, `M-0002`, ...) a `mitigations.yml`, actualiza las columnas
   Mitigation y `FINDINGS.md` sin llamar a Veracode, hace commit de `Approve mitigation M-000N (#incidencia)`,
   comenta "Approved as M-000N, applied to N finding(s)" y cierra la incidencia.

| Situación | Resultado |
| --- | --- |
| Quien añadió la etiqueta no es aprobador | Se quita la etiqueta y se comenta "@login is not an approver" |
| El formulario no es válido (clave, tipo o fecha incorrectos, falta el motivo, caducidad en el pasado) | Se quita la etiqueta y se comentan los problemas. Edita la incidencia y vuelve a añadir la etiqueta |
| La incidencia se editó después de añadir la etiqueta | Se quita la etiqueta. Revísala y vuelve a añadirla |
| Rechazar | Cierra la incidencia sin la etiqueta |

### Alcance de una solicitud

| Campo Asset | Campo File | La regla mitiga |
| --- | --- | --- |
| Sin cambios (como lo rellena el enlace) | Vacío | Solo este hallazgo (`finding` es su Finding Key) |
| Con comodín, por ejemplo `acme/payments-*` | Cualquiera | Este Finding ID en todos los assets que coincidan |
| Cualquiera | Un patrón de ruta, por ejemplo `modules/status/*` | Este Finding ID en los archivos que coincidan |

Se rechaza una regla que coincide con todo (`finding: "*"` sin asset ni file).

## mitigations.yml

La plantilla empieza con una lista vacía (`[]`). Las entradas tienen este aspecto
([examples/mitigations.example.yml](examples/mitigations.example.yml)):

```yaml
- id: M-0001
  finding: AVD-AWS-0086
  asset: acme/payments-*
  file: modules/status/*
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Campo | Obligatorio | Significado |
| --- | --- | --- |
| `id` | Sí | `M-` y al menos 4 dígitos, único. El workflow asigna el siguiente número libre |
| `finding` | Sí | Finding ID, CVE o Finding Key (`mk-...`). `*` y `?` son comodines; debe coincidir el valor completo; no distingue mayúsculas |
| `asset` | No | Asset Name o Asset ID, con comodines |
| `file` | No | File Path o Location, con comodines |
| `type` | Sí | Uno de los tipos de abajo |
| `reason` | Sí | Por qué el hallazgo no necesita corrección |
| `approved_by` | Sí | El aprobador. El workflow escribe el login de GitHub |
| `approved_on` | No | `AAAA-MM-DD`. Lo pone el workflow |
| `expires` | Para `accept-risk` | `AAAA-MM-DD`. Desde el día siguiente, el hallazgo vuelve a contar como abierto |
| `ref` | No | Enlace a la incidencia (lo pone el workflow), `migrated` o cualquier texto |
| `requested_by` | No | Autor de la incidencia. Lo pone el workflow |
| `notes` | No | Ticket o número de cambio |
| `allow_broad` | No | `true` para permitir una regla que coincide con todos los hallazgos |

Si varias reglas coinciden con un hallazgo, gana la primera del archivo que no haya caducado.

### Tipos (los mismos que en Static Analysis)

| Tipo | Cuándo usarlo | Nombre en Static Analysis |
| --- | --- | --- |
| `false-positive` | El hallazgo no es real | Potential False Positive |
| `by-design` | La configuración es intencionada y está aprobada | Mitigate by Design |
| `network-environment` | Un control de red lo bloquea (WAF, security group, red privada) | Mitigate by Network Environment |
| `os-environment` | El sistema operativo o el runtime lo bloquea (host bastionado, sistema de archivos de solo lectura, sin shell) | Mitigate by OS Environment |
| `accept-risk` | El negocio acepta el riesgo; requiere `expires` | Accept the Risk |

### Mitigation Status

| Valor | Significado |
| --- | --- |
| `Mitigated` | Coincide una regla y no ha caducado |
| `Expiring` | Caduca en 30 días o menos. Aparece en `FINDINGS.md` |
| `Expired` | Ha pasado la fecha de caducidad. Cuenta como abierto; aparece en `FINDINGS.md` con un enlace Mitigate para renovarla |
| (vacío) | No mitigado |

## Editar, renovar, revocar

- **Editar o añadir directamente:** cambia `mitigations.yml` en una pull request. El job `check` valida el
  archivo y comenta una tabla de las reglas añadidas, cambiadas o eliminadas, con cuántos hallazgos abiertos
  cubre cada una. El check ejecuta el script de la rama base, así que una pull request no puede cambiar cómo se
  comprueba. Falla si el archivo no es válido; configúralo como check obligatorio.
- **Renovar:** cambia `expires` en una pull request, o vuelve a solicitarla desde el enlace Mitigate.
- **Revocar:** borra la entrada en una pull request. La siguiente ejecución (o la siguiente aprobación) muestra
  los hallazgos como no mitigados.

Comprobación en local, sin acceso a Veracode:

```bash
python veracode_iac_extract.py --check-mitigations mitigations.yml
python veracode_iac_extract.py --check-mitigations mitigations.yml --against old.yml --track tracking   # tabla de la PR
python veracode_iac_extract.py -o findings.csv --mitigations mitigations.yml   # exportación con columnas Mitigation
```

| Flag | Efecto |
| --- | --- |
| `--mitigations ARCHIVO` | Aplica las reglas de `ARCHIVO` a `--track` o a una exportación |
| `--check-mitigations ARCHIVO` | Valida y lista las reglas: sale con 0 si es válido, 2 si no. Claves desconocidas, campos que faltan, tipos o fechas incorrectos e ids duplicados son errores; una caducidad en el pasado es un aviso |
| `--against BASE` | Con `--check-mitigations`: tabla Markdown de los cambios respecto a `BASE` (como máximo 60.000 caracteres) |
| `--track DIR` | Con `--against`: cuenta los hallazgos abiertos de `DIR/findings.csv` que cubre cada regla |
| `--approve-issue ARCHIVO` | Lo usa el workflow: convierte el JSON de la incidencia en `ARCHIVO` en una entrada. Sale con 2 si no es válida, 3 si no es aprobador |
| `--approver LOGIN` | Con `--approve-issue`: quién añadió la etiqueta. Se comprueba contra `MITIGATION_APPROVERS` |

## Notas de seguridad

- Solo quien puede añadir etiquetas (acceso triage o superior) puede lanzar una aprobación, y solo se aceptan
  los logins de `MITIGATION_APPROVERS`. Cambiar esa variable requiere acceso de administrador.
- Protege `mitigations.yml` y `.github/` con [CODEOWNERS](.github/CODEOWNERS) y protección de rama. Si no, quien
  tenga acceso de escritura puede editarlos directamente.
- El texto de la incidencia nunca llega a una shell: el workflow se lo pasa al script como archivo JSON. La
  incidencia se lee del evento de la etiqueta, y la aprobación se rechaza si se editó después.
- Todos los valores que aparecen en comentarios y en `FINDINGS.md` se escapan: sin HTML, sin comentarios
  ocultos, sin @menciones, sin romper tablas.
- El job diario y el de aprobación comparten un grupo de concurrencia, así que nunca escriben a la vez.

## Limitaciones

- Las mitigaciones solo afectan al seguimiento y a las exportaciones. No cambian la plataforma de Veracode, los
  resultados de políticas ni los controles del pipeline.
- La Finding Key cambia si el archivo se mueve o se renombra, si se renombra el recurso o si cambia el valor de un
  secreto. El hallazgo aparece entonces como New; vuelve a solicitar la mitigación, o usa una regla por Finding
  ID con alcance de asset o file.

## Paso desde el archivo CSV de seguimiento

Las versiones anteriores guardaban las mitigaciones en `veracode-findings.csv` (`--mitigations ARCHIVO.csv`,
`--convert`). En la primera ejecución de `--track`, si `veracode-findings.csv` está junto a la carpeta
`tracking` (o con `--migrate ARCHIVO`), cada fila mitigada pasa a ser una entrada de `mitigations.yml`
(`finding` = su clave, `ref: migrated`) y los hallazgos conservan su fecha First Seen. Después, el archivo
antiguo no se usa y se puede borrar. Las filas no válidas detienen la ejecución con el código 2 sin cambiar nada.
