import pytest
from core.streaming import KafkaToDuckDB
from core.active_learning import FPLearner
from kafka import KafkaProducer
import json
import time

def test_fp_filter_drops_noise():
    """v3.3: Entrena con 1 FP, verifica que el streamer lo descarta"""
    learner = FPLearner()

    # 1. Feedback: este cmdline es FP
    fp_event = {"image": "notepad.exe", "cmdline": "notepad.exe", "rule_id": "T1059"}
    learner.feedback(fp_event, is_false_positive=True)

    # Entrenar un poco más para asegurar que la prob suba
    for _ in range(5):
        learner.feedback(fp_event, is_false_positive=True)

    # 2. Simula streaming
    streamer = KafkaToDuckDB(fp_threshold=0.51)
    result = streamer.process_batch([fp_event])

    assert result['fp_dropped'] == 1, "FP no fue descartado"
    assert result['ingested'] == 0, "Evento FP llegó a DuckDB"

def test_kafka_roundtrip():
    """v3.4: Produce a Kafka, consume y verifica ingest"""
    producer = KafkaProducer(
        bootstrap_servers='localhost:9092',
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )

    test_event = {"process_guid": "test-123", "image": "test.exe",
                  "cmdline": "test", "ts": "2026-01-01T00:00:00Z",
                  "host": "TEST", "user": "test", "parent_process_guid": "root"}

    # Inicializar streamer ANTES para que se una al grupo
    import uuid
    streamer = KafkaToDuckDB(batch_size=1)
    # Cambiar a earliest para test
    streamer.consumer.config['auto_offset_reset'] = 'earliest'
    time.sleep(2) # Dar tiempo para unirse al grupo
    
    producer.send('siem_raw', test_event)
    producer.flush()

    # Da 2s a Kafka para propagar
    time.sleep(2)

    # Usar poll en loop para dar tiempo a asignacion de particiones
    records = {}
    for _ in range(10):
        records = streamer.consumer.poll(timeout_ms=1000)
        if records:
            break
            
    assert len(records) > 0, "No se recibieron mensajes de Kafka"
    msg = list(records.values())[0][0]
    assert msg.value['process_guid'] == "test-123"
