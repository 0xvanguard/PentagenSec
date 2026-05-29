# core/sigma_jit.py
import yaml
import subprocess
from pathlib import Path
import hashlib
import argparse
import sys
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sigma_jit")

def get_re_rules(rules_dir: Path):
    """Extrae regex de archivos Sigma."""
    regexes = []
    for sigma_file in rules_dir.glob('*.yml'):
        with open(sigma_file) as f:
            try:
                rule = yaml.safe_load(f)
                rule_id_str = rule.get('id', sigma_file.stem)
                rule_id = int(hashlib.sha1(rule_id_str.encode()).hexdigest(), 16) & 0xFFFFFFFF
                
                for det in rule.get('detection', {}).values():
                    if isinstance(det, dict) and 're' in det:
                        # Extraer el pattern sin los bounds de inicio/fin si no están estrictos
                        # En re2c strings son "str"
                        # Nota: re2c syntax requires careful escaping, simplified here
                        regexes.append((rule_id, det['re']))
            except Exception as e:
                log.error(f"Error parsing {sigma_file}: {e}")
    return regexes

def compile_batches(rules_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    regexes = get_re_rules(rules_dir)
    
    if not regexes:
        log.info("No regex rules found. Exiting.")
        return

    # Chunking en 28 (para límite 32 tail_calls)
    CHUNK_SIZE = 28
    batches = [regexes[i:i + CHUNK_SIZE] for i in range(0, len(regexes), CHUNK_SIZE)]
    
    template_path = Path("ebpf/trampoline.c")
    if not template_path.exists():
        log.error("Template ebpf/trampoline.c not found.")
        sys.exit(1)
        
    template = template_path.read_text()
    
    for idx, batch in enumerate(batches):
        re2c_rules_str = ""
        for rule_id, pattern in batch:
            # Escape de comillas dobles y caracteres conflictivos. Para re2c:
            escaped_pattern = pattern.replace('"', '\\"')
            re2c_rules_str += f'    "{escaped_pattern}" {{ return {rule_id}; }}\n'
            
        next_idx = idx + 1 if idx + 1 < len(batches) else 0xFFFFFFFF
        
        c_code = template.replace("{re2c_rules}", re2c_rules_str)
        c_code = c_code.replace("{next_idx}", str(next_idx))
        
        c_file = out_dir / f"chunk_{idx}.c"
        c_file.write_text(c_code)
        
        # Generar C con re2c
        subprocess.run(["re2c", "-W", "-o", str(c_file), str(c_file)], check=True)
        
        # Compilar a .o con clang
        o_file = out_dir / f"chunk_{idx}.o"
        subprocess.run([
            "clang", "-O2", "-target", "bpf", "-g", 
            "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu",
            "-c", str(c_file), "-o", str(o_file)
        ], check=True)
        
        log.info(f"Compiled chunk {idx}.o with {len(batch)} regexes.")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules-dir', required=True)
    parser.add_argument('--out-dir', required=True)
    args = parser.parse_args()
    
    compile_batches(Path(args.rules_dir), Path(args.out_dir))
