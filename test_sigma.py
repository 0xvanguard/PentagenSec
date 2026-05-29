import time
from core.sigma_compiler import SigmaDuckDB
from pathlib import Path

def test_duckdb():
    print("Iniciando test de SigmaDuckDB...")
    engine = SigmaDuckDB()
    
    # Ingest
    t0 = time.time()
    engine.ingest_siem_jsonl("samples/siem_events.json")
    t1 = time.time()
    print(f"[+] Ingesta completada en {(t1-t0)*1000:.2f}ms")
    
    # Hunt
    sigma_rule = Path("rules/t1059.yml").read_text()
    
    print("\n--- Sigma Rule to Compile ---")
    print(sigma_rule)
    
    print("\n--- Compiled SQL ---")
    print(engine.compile_sigma(sigma_rule))
    
    t0 = time.time()
    hits = engine.hunt(sigma_rule, last="90d")
    t1 = time.time()
    
    print(f"\n[+] Hunt completado en {(t1-t0)*1000:.2f}ms")
    print(f"Hits encontrados: {len(hits)}")
    for hit in hits:
        print(hit)

if __name__ == "__main__":
    test_duckdb()
