# Matriz de Cumplimiento NIST 800-53 Rev.5 (Antigravity 2.0)

| NIST ID | Control Name | Estado | Evidencia | Mitigación Recomendada |
| :--- | :--- | :--- | :--- | :--- |
| **SC-7** | Boundary Protection | **Fail** | `docker-compose.yml:33` (Expone puerto 11434 a 0.0.0.0 sin IP bind). | Bind explícito a `127.0.0.1:11434:11434` o aislar en red bridge interna. |
| **SI-10** | Information Input Validation | **Fail** | `main.py:355` (Usa `json.load()` genérico sobre input no confiable). | Implementar esquemas Pydantic estrictos para sanitizar `siem_events_path`. |
| **SI-16** | Memory Protection / Code Exec | **Pass** | Ausencia de `eval()`, `exec()`, `pickle`, y `subprocess` en código base. | Mantener política de "cero ejecución dinámica". |
| **SA-22** | Supply Chain Protection | **Fail** | `requirements.txt:7-22` (Usa rangos `<0.5`, carece de hashes SHA256). | Pinar dependencias con `==` y requerir `--hash=sha256` (e.g. vía `pip-tools`). |
| **CM-8** | Component Inventory | **Fail** | `Dockerfile:23,49` (Imágenes `FROM python:3.12` sin pinning `@sha256`). | Especificar SHA-256 digest para cada stage en el `Dockerfile`. |
| **SI-2** | Flaw Remediation | **Missing** | Falta lockfile completo, dificultando chequeo OSV.dev de dependencias transitivas. | Generar `requirements.txt` pineado con pip-audit o Safety en el pipeline CI/CD. |
| **AC-3** | Access Enforcement | **Partial** | `main.py:105-120` (Implementa deny-list primitiva `FORBIDDEN_BATCH_KEYS`). | Migrar a modelo LLM-Guard o Rebuff para prevención robusta de Prompt Injection. |
| **AC-6** | Least Privilege | **Pass** | `main.py:236` (Deshabilita `function_calling` explícitamente en AutoGen). | Mantener configuración. |
| **AC-4** | Information Flow Enforcement | **Pass** | `notifications.py` solo dispara peticiones pre-aprobadas, no controladas por IA. | Mantener política de aprobación manual (fail-closed) para cualquier webhook. |
| **AC-17** | Remote Access (Air Gap) | **Fail** | `docker-compose.yml:58` (Ejecuta `ollama pull qwen2.5-coder:7b` en runtime). | Pre-empaquetar o montar modelos `.gguf` en offline volume para operación sin red. |
| **AU-9** | Protection of Audit Information | **Fail** | `main.py:434` (Escribe `report_md` sin generar hash criptográfico para Chain-of-Custody). | Computar MD5+SHA256 del evento pre/post análisis y almacenar en `.sha256` / `.md5`. |
| **SI-4** | Information System Monitoring | **Missing** | Carece de exportación a SARIF 2.1.0 y banderas CLI (`--dry-run`, `--fail-on-critical`). | Integrar `sarif-om` para emitir reportes compatibles con GitHub Advanced Security. |
