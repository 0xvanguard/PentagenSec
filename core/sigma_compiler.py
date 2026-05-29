import duckdb
import yaml
from pathlib import Path
import time
from core.metrics import duckdb_query_duration, sigma_hits_total, events_ingested_total

class SigmaDuckDB:
    def __init__(self, db_path=":memory:"):
        self.con = duckdb.connect(db_path)
        self._init_schema()
    
    def _init_schema(self):
        # Tabla adaptada a nuestro formato siem_events.json actual
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                timestamp TIMESTAMP,
                source VARCHAR,
                message VARCHAR,
                severity VARCHAR
            )
        """)
        # Índices trigrama/texto para la búsqueda rápida en el mensaje crudo
        # Usamos ART index donde DuckDB lo permita, pero para LIKE %...% es un escaneo.
        # En una v3.1 real, extraeríamos esto a columnas JSON o VARCHAR en la ingesta.
    
    def ingest_siem_jsonl(self, path: str):
        # Ingesta usando read_json_auto para cargar en la tabla base
        self.con.execute(f"INSERT INTO events SELECT CAST(timestamp AS TIMESTAMP), source, message, severity FROM read_json_auto('{path}')")
        
    def ingest_events_batch(self, events):
        """v3.0: Ingesta batch en memoria"""
        events_ingested_total.inc(len(events))
        # Para simplificar, ignoramos la inserción real en la tabla siem_events
        # ya que este es el mock provisto.
        pass

    def run_all_rules(self):
        """Mock para el pre-filtro completo"""
        start = time.time()
        with duckdb_query_duration.labels(query_type='pre_filter').time():
            results = {} # mock logic
        
        for rule_id, data in results.items():
            sigma_hits_total.labels(rule_id=rule_id, severity=data['severity']).inc(len(data['hits']))

        duckdb_query_duration.labels(query_type='pre_filter').observe(time.time() - start)
        return results
    
    def compile_sigma(self, sigma_yaml: str) -> str:
        """Convierte un subconjunto de Sigma a SQL DuckDB"""
        rule = yaml.safe_load(sigma_yaml)
        detection = rule['detection']
        sel = detection['selection']
        where = []
        
        # Mapeamos los campos Sigma a sub-cadenas dentro del campo `message` 
        # (ya que nuestros logs actuales de prueba vienen en un string concatenado)
        if 'Image|endswith' in sel:
            where.append(f"message LIKE '%Image=%{sel['Image|endswith']}%'")
        if 'CommandLine|contains' in sel:
            for val in sel['CommandLine|contains']:
                where.append(f"message ILIKE '%CommandLine=%{val}%'")
                
        # Fallback si WHERE está vacío
        if not where:
            return "SELECT * FROM events"
            
        return f"SELECT * FROM events WHERE {' AND '.join(where)}"
    
    def hunt(self, sigma_rule: str, last: str = "90d") -> list:
        sql = self.compile_sigma(sigma_rule)
        interval_val = last.replace('d', ' DAY')
        # Filtro de tiempo
        sql += f" AND timestamp >= current_timestamp - INTERVAL {interval_val}"
        return self.con.execute(sql).fetchall()

    def get_recent_hits(self, limit=500) -> list[dict]:
        """v4.0: Para TUI. Retorna últimos hits con metadata completa"""
        query = f"""
            SELECT
                event_id, ts, host, severity, rule_id, image, cmdline,
                user, process_guid, parent_process_guid
            FROM hits
            ORDER BY ts DESC
            LIMIT {limit}
        """
        try:
            return self.con.execute(query).fetchdf().to_dict('records')
        except duckdb.CatalogException:
            # Table doesn't exist in dummy db, return empty
            return []

    def get_event_by_id(self, event_id: str) -> dict | None:
        """v4.0: Drill-down por event_id"""
        query = "SELECT * FROM events WHERE event_id =? LIMIT 1"
        try:
            df = self.con.execute(query, [event_id]).fetchdf()
            return df.to_dict('records')[0] if not df.empty else None
        except duckdb.CatalogException:
            return None

    def compile_to_ebpf(self, sigma_yaml_path: str) -> list[dict]:
        """v4.2: Sigma → struct sigma_rule. Solo soporta selection con 'contains'."""
        import yaml
        with open(sigma_yaml_path) as f:
            rule = yaml.safe_load(f)

        ebpf_rules = []
        rule_id = hash(rule['id']) & 0xFFFFFFFF # 32-bit ID

        for sel in rule.get('detection', {}).get('selection', []):
            if 'contains' in sel:
                ebpf_rules.append({
                    'id': rule_id,
                    'dst_port': rule.get('port', 0),
                    'pattern': sel['contains']
                })
        return ebpf_rules

if __name__ == "__main__":
    import sys
    engine = SigmaDuckDB()
    engine.ingest_siem_jsonl("../samples/siem_events.json")
    print(f"Total events ingested: {engine.con.execute('SELECT COUNT(*) FROM events').fetchone()[0]}")
