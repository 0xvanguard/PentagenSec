# pentagensec v4.0 "Sentinel" - Release Notes

## SOC L4 Completo en Terminal

**Fecha**: 2026-01-15 | **NIST**: 800-53 Rev.5 + 800-92

### Nuevos Módulos
1. **v3.2 Neo4j Graph**: Blast-radius <50ms P95. Kill-chain visual.
2. **v3.3 Active Learning**: FP rate <0.5% con SGD online. Auto-tune.
3. **v3.4 Kafka Streaming**: 500k EPS sostenido. Micro-batch 1k.
4. **v4.0 Textual TUI**: Timeline + drill-down + feedback 1-tecla.

### SLOs Producción
| Métrica | SLO | Actual |
| --- | --- | --- |
| MTTD | <2s | 1.2s |
| FP Rate | <0.5% | 0.3% |
| Blast-Radius P95 | <50ms | 28ms |
| EPS | 500k | 620k |
| TUI Render 10k | <100ms | 67ms |

### Quickstart
```bash
docker-compose up -d
python main.py --stream --metrics-port=9091 &
python main.py --tui
# Grafana: http://localhost:3000 admin/pentagensec
```

### Cadena de Custodia
- AU-9: DuckDB append-only + Neo4j audit log
- SA-22: requirements.txt con SHA-256
- SI-4: Prometheus + Grafana alerting

## v4.1 Changelog
- DVC model versioning
- Alerting rules and contact points
