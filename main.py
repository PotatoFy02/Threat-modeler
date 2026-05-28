import json
import sys
from models import Component
from stride_engine import analyze
from report_generator import print_console_report, generate_pdf_report

def load_system(filepath: str):
    with open(filepath, "r") as f:
        data = json.load(f)
    components = [Component(**c) for c in data["components"]]
    return data["system_name"], components

def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "sample_input.json"
    print(f"\nLoading system definition from '{filepath}'...")
    
    system_name, components = load_system(filepath)
    print(f"Loaded {len(components)} components. Running STRIDE analysis...\n")
    
    threats = analyze(components)
    print_console_report(threats, system_name)
    generate_pdf_report(threats, system_name, "threat_report.pdf")

if __name__ == "__main__":
    main()