# gcpsec

CLI open source para auditar y mejorar la seguridad de credenciales en Google Cloud.

`gcpsec` nace para operacionalizar recomendaciones como:
- No guardar claves en el código fuente.
- Revisar y desactivar claves inactivas.
- Restringir API keys por API y entorno.
- Aplicar políticas de rotación y bloqueo de creación de claves.
- Verificar contactos críticos para respuesta a incidentes.

## Estado del proyecto

MVP funcional en Go, sin dependencias externas.

Comandos incluidos:
- `scan`: ejecuta checks y guarda resultados en JSON.
- `recommend`: convierte hallazgos en acciones priorizadas.
- `enforce`: aplica remediaciones seguras (dry-run por defecto).
- `report`: renderiza `json`, `markdown` o `sarif`.

## Requisitos

- Go 1.22+
- `gcloud` autenticado para checks remotos (opcional para scan local)

## Instalación local

```bash
git clone https://github.com/Andrei-Barwood/gcpsec.git
cd gcpsec
go build -o bin/gcpsec ./cmd/gcpsec
```

## Uso rápido

1) Escaneo local + proyecto GCP

```bash
./bin/gcpsec scan \
  --project my-gcp-project \
  --repo . \
  --inactive-days 30 \
  --out .gcpsec/scan.json
```

2) Recomendaciones priorizadas

```bash
./bin/gcpsec recommend --from .gcpsec/scan.json --format table
```

3) Reporte SARIF para GitHub Security

```bash
./bin/gcpsec report \
  --from .gcpsec/scan.json \
  --format sarif \
  --out .gcpsec/results.sarif
```

4) Enforce en dry-run

```bash
./bin/gcpsec enforce --from .gcpsec/scan.json --project my-gcp-project
```

5) Enforce real (solo acciones soportadas)

```bash
./bin/gcpsec enforce --from .gcpsec/scan.json --project my-gcp-project --apply
```

## Checks actuales (MVP)

- **Zero-Code Storage**
  - Busca patrones de API keys y bloques de private key en repositorio.
- **API Key Restrictions**
  - Detecta API keys sin restricciones o restricciones incompletas.
- **Disable Dormant Keys (heurístico)**
  - Marca claves de service accounts antiguas para revisión/desactivación.
- **Mandatory Rotation**
  - Revisa políticas:
    - `constraints/iam.serviceAccountKeyExpiryHours`
    - `constraints/iam.managed.disableServiceAccountKeyCreation`
- **Incident Readiness**
  - Verifica Essential Contacts.

## Integración con GitHub Actions

Workflow incluido: `.github/workflows/ci.yml`.

Hace:
- `go test ./...`
- `scan` (si se entrega `GCP_PROJECT_ID`)
- genera `SARIF` y lo sube al Security tab de GitHub

Secrets necesarios en el repo:
- `WIF_PROVIDER`
- `WIF_SERVICE_ACCOUNT`
- `GCP_PROJECT_ID`

## Estructura

```text
cmd/gcpsec/main.go
internal/cli/
internal/scanner/
internal/format/
internal/report/
```

## Roadmap sugerido

- Integrar Cloud Logging para validar inactividad real de claves (no solo antigüedad).
- Añadir check de IAM Recommender para permisos no usados.
- Añadir check de alertas de presupuesto/anomalías de billing.
- Publicar Homebrew tap y release binaries.

## Licencia

MIT
