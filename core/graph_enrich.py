from neo4j import GraphDatabase
import networkx as nx
from core.metrics import graph_query_duration

class Neo4jEnricher:
    """v3.2: Graph de procesos para blast-radius <50ms"""
    def __init__(self, uri="bolt://localhost:7687"):
        self.driver = GraphDatabase.driver(uri, auth=("neo4j", "antigravity"))
        self._init_schema()

    def _init_schema(self):
        with self.driver.session() as s:
            s.run("CREATE INDEX proc_guid IF NOT EXISTS FOR (p:Process) ON (p.guid)")
            s.run("CREATE INDEX host_name IF NOT EXISTS FOR (h:Host) ON (h.name)")

    def ingest_event(self, event: dict):
        """Ingesta evento -> nodos Process, Host, User"""
        with self.driver.session() as s:
            s.run("""
                MERGE (h:Host {name: $host})
                MERGE (u:User {name: $user})
                MERGE (p:Process {guid: $guid, image: $image, cmdline: $cmdline, ts: $ts})
                MERGE (pp:Process {guid: $parent_guid})
                MERGE (p)-[:CHILD_OF]->(pp)
                MERGE (p)-[:RUN_ON]->(h)
                MERGE (p)-[:RUN_BY]->(u)
            """, host=event.get('host', 'unknown'), user=event.get('user', 'unknown'), guid=event.get('process_guid', 'unknown'),
                 image=event.get('image', ''), cmdline=event.get('cmdline', ''), ts=event.get('ts', ''),
                 parent_guid=event.get('parent_process_guid', 'unknown'))

    def blast_radius(self, process_guid: str, depth: int = 3) -> dict:
        """v3.2: Devuelve árbol de impacto en <50ms"""
        with graph_query_duration.time():
            with self.driver.session() as s:
                result = s.run("""
                    MATCH path = (p:Process {guid: $guid})-[*1..%d]-(related)
                RETURN related, relationships(path) as rels
            """ % depth, guid=process_guid)
            nodes = []
            edges = []
            for r in result:
                nodes.append(dict(r["related"]))
                edges.append(r["rels"])
            return {"nodes": nodes, "edges": edges}
