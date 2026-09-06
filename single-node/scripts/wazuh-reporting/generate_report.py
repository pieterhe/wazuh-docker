#!/usr/bin/env python3
import os
import re
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(BASE_DIR, "collector.py")
REPORT_GENERATOR = os.path.join(BASE_DIR, "report_generator.py")

def validate_tenant(value):
    tenant = value.strip()
    if not re.fullmatch(r"tenant_[A-Za-z0-9_-]+", tenant):
        raise ValueError("Ongeldige tenantnaam. Gebruik bijvoorbeeld: tenant_picard")
    return tenant

def run_step(label, script, tenant):
    print("\n" + "=" * 60)
    print(label)
    print("=" * 60)
    if not os.path.exists(script):
        raise FileNotFoundError(f"Script niet gevonden: {script}")
    result = subprocess.run([sys.executable, script, tenant], cwd=BASE_DIR)
    if result.returncode != 0:
        raise RuntimeError(f"{label} is mislukt (exitcode {result.returncode}).")

def main():
    if len(sys.argv) != 2:
        print(f"Gebruik: python {os.path.basename(sys.argv[0])} tenant_naam")
        print("Voorbeeld: python generate_report.py tenant_picard")
        sys.exit(2)
    try:
        tenant = validate_tenant(sys.argv[1])
        print(f"Wazuh rapportage starten voor: {tenant}")
        run_step("STAP 1/2 - Data verzamelen", COLLECTOR, tenant)
        run_step("STAP 2/2 - PDF rapport genereren", REPORT_GENERATOR, tenant)
        pdf_file = os.path.join(BASE_DIR, "output", f"{tenant}-security-report.pdf")
        print("\n" + "=" * 60)
        print("RAPPORTAGE SUCCESVOL AFGEROND")
        print("=" * 60)
        print(f"Tenant: {tenant}")
        print(f"PDF: {pdf_file}")
    except Exception as exc:
        print("\n" + "=" * 60)
        print("RAPPORTAGE AFGEBROKEN")
        print("=" * 60)
        print(f"Fout: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
