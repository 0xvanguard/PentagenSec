import json
import tiktoken

def estimate_tokens(events: list) -> int:
    """Estima tokens para métrica LLM_TOKENS_SAVED"""
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(json.dumps(events)))

def select_for_llm(all_hits: dict, max_events: int = 20, max_bytes: int = 8192) -> dict:
    """
    Contrato K=20 / 8KB: Deduplica, prioriza por severity, trunca.
    Si >20 eventos, devuelve resumen estadístico + top 5 evidencia.
    """
    flat_events = []
    for rule_id, data in all_hits.items():
        for hit in data['hits']:
            # DuckDB retorns tuples. Let's convert them to dict based on our schema
            # Schema: timestamp, source, message, severity
            # If hit is a tuple, convert to dict. If it's already a dict, just use it.
            if isinstance(hit, tuple) and len(hit) >= 4:
                 ev = {
                     'ts': str(hit[0]),
                     'source': hit[1],
                     'message': hit[2],
                     'severity': hit[3],
                     '_rule_id': rule_id,
                     '_rule_level': data['rule']['level']
                 }
            else:
                ev = dict(hit)
                ev['_rule_id'] = rule_id
                ev['_rule_level'] = data['rule']['level']
            flat_events.append(ev)
    
    # Deduplicar por process_guid si existe
    seen = set()
    deduped = []
    for ev in flat_events:
        key = ev.get('process_guid') or json.dumps(ev, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(ev)
    
    # Ordenar: critical > high > medium > low, luego timestamp desc
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    deduped.sort(key=lambda x: (sev_order.get(x.get('_rule_level', 'low'), 3), x.get('ts', '')), reverse=True)
    
    # Truncar a K=20 y 8KB
    result = {'events': [], 'summary': {}}
    current_bytes = 2  # {}
    
    if len(deduped) > max_events:
        result['summary'] = {
            'total_hits': len(deduped),
            'truncated': True,
            'top_rules': list(all_hits.keys())[:5]
        }
        deduped = deduped[:max_events]
    
    for ev in deduped:
        ev_bytes = len(json.dumps(ev).encode())
        if current_bytes + ev_bytes > max_bytes:
            result['summary']['truncated_due_to_size'] = True
            break
        result['events'].append(ev)
        current_bytes += ev_bytes
    
    return result
