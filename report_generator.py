from models import Threat
from typing import List
from tabulate import tabulate
from colorama import Fore, Style, init
from fpdf import FPDF

init(autoreset=True)

RISK_COLORS = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.GREEN,
}

def print_console_report(threats: List[Threat], system_name: str):
    print(f"\n{'='*60}")
    print(f"  STRIDE THREAT MODEL REPORT — {system_name.upper()}")
    print(f"{'='*60}")
    print(f"  Total Threats Found: {len(threats)}")
    high = sum(1 for t in threats if t.risk_level == "HIGH")
    medium = sum(1 for t in threats if t.risk_level == "MEDIUM")
    print(f"  HIGH: {high}  MEDIUM: {medium}  LOW: {len(threats)-high-medium}\n")

    rows = []
    for i, t in enumerate(threats, 1):
        color = RISK_COLORS.get(t.risk_level, "")
        rows.append([
            i,
            color + t.risk_level + Style.RESET_ALL,
            t.stride_category,
            t.affected_component,
            t.title,
        ])

    print(tabulate(rows, headers=["#", "Risk", "STRIDE", "Component", "Threat"], tablefmt="rounded_outline"))

    print("\nDETAILED FINDINGS & MITIGATIONS:\n")
    for i, t in enumerate(threats, 1):
        color = RISK_COLORS.get(t.risk_level, "")
        print(f"{i}. [{color}{t.risk_level}{Style.RESET_ALL}] {t.title} ({t.stride_category})")
        print(f"   Component  : {t.affected_component}")
        print(f"   Description: {t.description}")
        print(f"   Mitigation : {t.mitigation}\n")

def generate_pdf_report(threats: List[Threat], system_name: str, filename: str = "threat_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"Threat Model Report: {system_name}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Total Threats: {len(threats)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    for i, t in enumerate(threats, 1):
        pdf.set_font("Helvetica", "B", 12)
        if t.risk_level == "HIGH":
            pdf.set_text_color(200, 0, 0)
        elif t.risk_level == "MEDIUM":
            pdf.set_text_color(180, 120, 0)
        else:
            pdf.set_text_color(0, 150, 0)
        pdf.cell(0, 8, f"{i}. [{t.risk_level}] {t.title}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, f"STRIDE Category: {t.stride_category}\nComponent: {t.affected_component}\nDescription: {t.description}\nMitigation: {t.mitigation}")
        pdf.ln(3)

    pdf.output(filename)
    print(f"\nPDF report saved as '{filename}'")