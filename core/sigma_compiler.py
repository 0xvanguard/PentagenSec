import duckdb
import yaml
from pathlib import Path

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

if __name__ == "__main__":
    import sys
    engine = SigmaDuckDB()
    engine.ingest_siem_jsonl("../samples/siem_events.json")
    print(f"Total events ingested: {engine.con.execute('SELECT COUNT(*) FROM events').fetchone()[0]}")
