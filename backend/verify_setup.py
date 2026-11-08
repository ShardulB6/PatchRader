"""Minimal environment/dataset check (stdlib only)."""
from pathlib import Path
import importlib.util
import sys
p=Path(__file__).resolve().parent
print('Python:',sys.executable)
for module in ('streamlit','duckdb','pandas','plotly','dotenv'):
    print(f'{module}:', 'installed' if importlib.util.find_spec(module) else 'MISSING')
required=('vulnerabilities.csv','affected_products.csv','known_exploited.csv','scoreboard_2026.csv')
for name in required:
    print(f'data/{name}:', 'found' if (p/'data'/name).is_file() else 'MISSING')
print('See README.md for installation and data placement.')
