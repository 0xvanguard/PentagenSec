#!/usr/bin/env python3
"""
v3.2 Test: Neo4j Blast-Radius <50ms
NIST: Prueba de rendimiento para SOC L4
"""
import time
import pytest
from core.graph_enrich import Neo4jEnricher

@pytest.fixture(scope="module")
def graph():
    """Setup: Conecta a Neo4j y limpia BD de test"""
    g = Neo4jEnricher("bolt://localhost:7687")
    with g.driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")  # Limpia
    yield g
    g.driver.close()

def test_blast_radius_latency_and_accuracy(graph):
    """
    1. Ingesta 3 procesos: A -> B -> C
    2. Query blast-radius desde A, depth=3
    3. Valida que retorna B y C en <50ms
    """
    # 1. Dataset sintético: cadena de procesos
    events = [
        {
            "process_guid": "proc-A", "parent_process_guid": "proc-root",
            "image": "cmd.exe", "cmdline": "cmd.exe /c start", "ts": "2026-01-01T00:00:00Z",
            "host": "HOST01", "user": "admin"
        },
        {
            "process_guid": "proc-B", "parent_process_guid": "proc-A",
            "image": "powershell.exe", "cmdline": "powershell -enc XYZ", "ts": "2026-01-01T00:00:01Z",
            "host": "HOST01", "user": "admin"
        },
        {
            "process_guid": "proc-C", "parent_process_guid": "proc-B",
            "image": "mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords", "ts": "2026-01-01T00:00:02Z",
            "host": "HOST01", "user": "admin"
        },
    ]
    
    for ev in events:
        graph.ingest_event(ev)
    
    # 2. Benchmark blast-radius
    start = time.time()
    radius = graph.blast_radius("proc-A", depth=3)
    duration_ms = (time.time() - start) * 1000
    
    # 3. Asserts NIST L4
    assert duration_ms < 50, f"Blast-radius tardó {duration_ms:.2f}ms, SLO es <50ms"
    
    node_images = {n["image"] for n in radius["nodes"]}
    assert "powershell.exe" in node_images, "Falta nodo B en blast-radius"
    assert "mimikatz.exe" in node_images, "Falta nodo C en blast-radius"
    assert len(radius["nodes"]) >= 2, "Grafo incompleto"
    
    print(f"[+] Blast-radius OK: {len(radius['nodes'])} nodos en {duration_ms:.2f}ms")

def test_blast_radius_empty():
    """Valida que un GUID inexistente no crashea"""
    g = Neo4jEnricher()
    radius = g.blast_radius("proc-NOEXISTE", depth=3)
    assert radius["nodes"] == [], "Debe retornar grafo vacío"
    g.driver.close()
