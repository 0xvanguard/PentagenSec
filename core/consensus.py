from enum import Enum
import hashlib

class TriagePath(Enum):
    FAST = "fast_path"      # Solo Gemini, 0.3s
    SLOW = "slow_path"      # Gemini + Claude, 1.8s
    MANUAL = "manual_review" # Discrepancia

class AsymmetricConsensus:
    def __init__(self, gemini, claude, custody):
        self.gemini = gemini
        self.claude = claude
        self.custody = custody
    
    def classify(self, payload: dict) -> TriagePath:
        # Extraemos variables elevadas al nivel del payload/summary
        summary = payload.get('summary', {})
        is_critical = summary.get('severity') == 'critical'
        has_ioc = summary.get('ioc_hit', False)
        sigma_high = summary.get('sigma_level') == 'high' or summary.get('sigma_level') == 'critical'
        high_conf = summary.get('sigma_confidence', 0) > 0.9
        
        # Fast-path rules: Critical + IOC + Sigma High + Confidence >0.9
        if is_critical and has_ioc and sigma_high and high_conf:
            return TriagePath.FAST
        
        # Slow-path: Medium, Low, o falta IOC/confidence
        return TriagePath.SLOW
    
    def triage(self, payload: dict) -> dict:
        path = self.classify(payload)
        prompt_hash = hashlib.sha256(str(payload).encode()).hexdigest()
        
        if path == TriagePath.FAST:
            self.custody.log("consensus_fast", prompt_hash=prompt_hash, skip_claude=True)
            verdict = self.gemini.analyze(payload)
            verdict['consensus_path'] = 'fast'
            verdict['claude_skipped'] = True
            return verdict
        
        # Slow path: doble consenso
        g_verdict = self.gemini.analyze(payload)
        c_verdict = self.claude.analyze(payload)
        
        # Si discrepan en severity, escalan a manual
        if g_verdict['severity'] != c_verdict['severity']:
            self.custody.log("consensus_conflict", prompt_hash=prompt_hash)
            return {'severity': 'manual_review', 'gemini': g_verdict, 'claude': c_verdict, 'findings': g_verdict.get('findings', [])}
        
        self.custody.log("consensus_slow", prompt_hash=prompt_hash, agreement=True)
        return {'severity': g_verdict['severity'], 'consensus_path': 'slow', 'confidence': 1.0, 'findings': g_verdict.get('findings', [])}
