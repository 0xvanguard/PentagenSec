import json
import time
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from core.sigma_compiler import SigmaDuckDB
from core.graph_enrich import Neo4jEnricher
from core.active_learning import FPLearner
import logging
from core.metrics import kafka_batch_duration, fp_dropped_total, fp_probability

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("streaming")

class KafkaToDuckDB:
    """v3.4: Ingesta continua Kafka → DuckDB + Neo4j + FP filter"""

    def __init__(self,
                 kafka_bootstrap='localhost:9092',
                 topic='siem_raw',
                 batch_size=1000,
                 fp_threshold=0.8):
        self.consumer = KafkaConsumer(
            topic,
            bootstrap_servers=[kafka_bootstrap],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            enable_auto_commit=False, # Commit manual tras persistir
            group_id='antigravity-v4'
        )
        self.db = SigmaDuckDB()
        self.graph = Neo4jEnricher()
        self.fp_learner = FPLearner()
        self.batch_size = batch_size
        self.fp_threshold = fp_threshold # v3.3: auto-descarta si FP prob > 0.8

    def process_batch(self, events: list) -> dict:
        """Pipeline: DuckDB ingest → Neo4j enrich → FP filter → Sigma"""
        with kafka_batch_duration.time():
            start = time.time()
    
            # 1. v3.3 Active Learning: filtra FPs antes de gastar CPU
            filtered_events = []
            fp_dropped = 0
            for ev in events:
                fp_prob = self.fp_learner.predict_fp_prob(ev)
                fp_probability.observe(fp_prob)
                if fp_prob < self.fp_threshold:
                    filtered_events.append(ev)
                else:
                    fp_dropped += 1
                    fp_dropped_total.inc()
                    log.debug(f"FP dropped: {ev.get('cmdline', '')[:50]} prob={fp_prob:.2f}")

        if not filtered_events:
            return {"ingested": 0, "fp_dropped": fp_dropped, "hits": 0}

        # 2. v3.0 DuckDB: bulk insert
        self.db.ingest_events_batch(filtered_events)

        # 3. v3.2 Neo4j: enriquece grafo para blast-radius
        for ev in filtered_events:
            if ev.get('process_guid'): # Solo eventos de proceso
                self.graph.ingest_event(ev)

        # 4. v3.0 Sigma: corre reglas sobre el batch
        hits = self.db.run_all_rules() # Retorna dict {rule_id: {rule, hits}}

        duration_ms = (time.time() - start) * 1000
        log.info(f"Batch: {len(filtered_events)} eventos, {fp_dropped} FPs, "
                 f"{sum(len(h['hits']) for h in hits.values())} hits en {duration_ms:.1f}ms")

        return {
            "ingested": len(filtered_events),
            "fp_dropped": fp_dropped,
            "hits": hits,
            "duration_ms": duration_ms
        }

    def run(self):
        """Loop infinito: consume Kafka → procesa micro-batches"""
        batch = []
        log.info(f"Streaming iniciado. Topic: {self.consumer.subscription()}")

        try:
            for msg in self.consumer:
                batch.append(msg.value)

                if len(batch) >= self.batch_size:
                    result = self.process_batch(batch)
                    self.consumer.commit() # AU-9: commit solo tras persistir
                    batch = []
                    yield result # Para TUI o métricas

        except KafkaError as e:
            log.error(f"Kafka error: {e}")
        finally:
            self.consumer.close()
            self.graph.driver.close()
