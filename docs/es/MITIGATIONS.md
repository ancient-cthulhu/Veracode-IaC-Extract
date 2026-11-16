# Mitigaciones

[English](../MITIGATIONS.md) | Español

La Veracode Platform no tiene mitigaciones para los hallazgos de Container, IaC y Secrets. El
[seguimiento de hallazgos](README.md#seguimiento-de-hallazgos-recomendado) las registra en `mitigations.yml`
y las muestra en `FINDINGS.md`, `tracking/findings.csv` y en cada exportación.

## Solicitar y aprobar

1. **Solicitar.** En `FINDINGS.md`, pulsa **Mitigate** en el hallazgo. Se abre una incidencia ya rellenada. Elige
   el tipo, escribe el motivo, añade una fecha de caducidad (obligatoria para `accept-risk`) y envíala.
2. **Aprobar.** Un aprobador (un login de la variable `MITIGATION_APPROVERS`) añade la etiqueta `approved`.
3. **Listo.** El bot añade la siguiente entrada (`M-0001`, `M-0002`, ...) a `mitigations.yml`, actualiza el panel,
   comenta "Approved as M-0001, applied to 1 finding(s)" y cierra la incidencia.

| Situación | Resultado |
| --- | --- |
| La etiqueta la añadió alguien que no es aprobador | Se quita la etiqueta, con un comentario |
| El formulario no es válido (falta el motivo, tipo o fecha incorrectos) | Se quita la etiqueta y se listan los problemas. Corrige la incidencia y vuelve a etiquetarla |
| La incidencia se editó después de la etiqueta | Se quita la etiqueta. Revísala y vuelve a etiquetarla |
| Rechazar | Cierra la incidencia sin la etiqueta |

### Alcance

| Campo Asset | Campo File | Mitiga |
| --- | --- | --- |
| Tal como lo rellena el enlace | Vacío | Solo este hallazgo |
| Comodín, por ejemplo `acme/payments-*` | Cualquiera | Este Finding ID en cada asset que coincida |
| Cualquiera | Patrón de ruta, por ejemplo `modules/status/*` | Este Finding ID en los archivos que coincidan |

## mitigations.yml

```yaml
- id: M-0001
  finding: AVD-AWS-0086
  asset: acme/payments-*
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Campo | Obligatorio | Significado |
| --- | --- | --- |
| `id` | Sí | Formato `M-0001`, único |
| `finding` | Sí | Finding ID, CVE o Finding Key (`mk-...`). Comodines `*` y `?`, valor completo, sin distinguir mayúsculas |
| `asset` | No | Asset Name o Asset ID, admite comodines |
| `file` | No | Ruta del archivo, admite comodines |
| `type` | Sí | Ver abajo |
| `reason` | Sí | Por qué no hace falta corregirlo |
| `approved_by` | Sí | Aprobador |
| `approved_on`, `requested_by`, `ref` | No | Los pone el bot (`ref` es el enlace a la incidencia) |
| `expires` | Para `accept-risk` | `YYYY-MM-DD`. Desde el día siguiente el hallazgo cuenta como abierto |
| `notes` | No | Ticket o número de cambio |
| `allow_broad` | No | `true` para permitir una regla que coincide con todos los hallazgos |

Si coinciden varias reglas, gana la primera sin caducar del archivo. Más ejemplos:
[examples/mitigations.example.yml](../../examples/mitigations.example.yml).

| Tipo | Cuándo usarlo |
| --- | --- |
| `false-positive` | El hallazgo no es real |
| `by-design` | La configuración es intencionada y está aprobada |
| `network-environment` | Un control de red lo bloquea (WAF, security group, red privada) |
| `os-environment` | El sistema operativo o el runtime lo bloquea (host bastionado, sistema de archivos de solo lectura) |
| `accept-risk` | El negocio acepta el riesgo hasta `expires` |

| Mitigation Status | Significado |
| --- | --- |
| `Mitigated` | Una regla coincide y no ha caducado |
| `Expiring` | Caduca en 30 días o menos |
| `Expired` | Pasada la fecha `expires`; cuenta como abierto. Renuévala desde el enlace Mitigate |

## Editar, renovar, revocar

Cambia `mitigations.yml` en un pull request: edita o añade una regla, amplía `expires`, o borra una entrada para
revocarla. El pull request recibe un comentario con las reglas añadidas, cambiadas o eliminadas y cuántos
hallazgos abiertos cubre cada una, y la comprobación falla si el archivo no es válido. Hazla obligatoria.

```bash
python veracode_iac_extract.py --check-mitigations mitigations.yml                  # validar
python veracode_iac_extract.py -o findings.csv --mitigations mitigations.yml        # exportar con mitigaciones
```

## Seguridad

- Solo los logins de `MITIGATION_APPROVERS` pueden aprobar; cambiar la variable requiere acceso de administrador.
- Protege `mitigations.yml` y `.github/` con [CODEOWNERS](../../.github/CODEOWNERS) y protección de rama.
- El texto de la incidencia nunca llega a una shell, y todo lo que se muestra en comentarios y en `FINDINGS.md`
  se escapa.
- La comprobación del pull request usa el script de la rama base, así que un pull request no puede cambiar su
  propia comprobación.

## Limitaciones

- Las mitigaciones se aplican solo al seguimiento y a las exportaciones, no a la Veracode Platform, las políticas
  ni las puertas de los pipelines.
- Un Finding Key cambia si se renombra el archivo o el recurso, o si cambia el valor de un secreto. El hallazgo
  aparece entonces como New; mitígalo de nuevo, o usa una regla por Finding ID con alcance de asset o archivo.

## veracode-findings.csv existente

Si hay un `veracode-findings.csv` con mitigaciones junto a la carpeta `tracking`, la primera ejecución copia sus
mitigaciones a `mitigations.yml` (`ref: migrated`) y conserva el First Seen de cada hallazgo. Después se puede
borrar el CSV.
