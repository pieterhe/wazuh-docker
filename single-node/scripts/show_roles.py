python3 -c "
import subprocess, json
result = subprocess.run(
    ['docker', 'exec', 'single-node-wazuh.indexer-1', 'curl', '-sk',
     '-u', 'admin:ais;aCahze9vi#',
     'https://localhost:9200/_plugins/_security/api/roles/'],
    capture_output=True, text=True
)
roles = json.loads(result.stdout)
for r in sorted(roles.keys()):
    print(r)
"
