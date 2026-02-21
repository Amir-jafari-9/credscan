#!/bin/bash
set -e

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

python -c "
import yaml
from credscan.core import Scanner
from pathlib import Path

config = yaml.safe_load(open('config.yaml'))
scanner = Scanner(config)

for path_str in config['search_paths']:
    path = Path(path_str)
    if not path.exists():
        continue
        
    for file_path in path.rglob('*'):
        if file_path.is_file():
            results = scanner.scan_file(file_path)
            
            with open(config['output']['passwords_file'], 'a') as f:
                f.write('\\n'.join(scanner.generate_output(file_path, results, 'passwords')) + '\\n')
            
            with open(config['output']['urls_file'], 'a') as f:
                f.write('\\n'.join(scanner.generate_output(file_path, results, 'urls')) + '\\n')

print('✅ Scan complete! Results in ' + config['output']['passwords_file'] + ' and ' + config['output']['urls_file'])
"
