import requests
import time

# ─── CONFIG ───────────────────────────────────────────
TARGET_URL = ""
PAYLOAD_FILE = "payloads.txt"
REPORT_FILE = "report.txt"

# Fields to fuzz — adjust to match the actual form field names
POST_DATA = {
    "username": "",
    "password": "test123"
}
FUZZ_FIELD = "username"  # which field we're injecting into

# DB error signatures to detect
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error",
    "mysql_fetch",
    "mysqli_fetch",
]

# ─── LOAD PAYLOADS ────────────────────────────────────
def load_payloads(filepath):
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

# ─── CHECK RESPONSE FOR ERRORS ────────────────────────
def detect_error(response_text):
    lower = response_text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in lower:
            return sig
    return None

# ─── SEND PAYLOAD ─────────────────────────────────────
def send_payload(session, payload):
    data = POST_DATA.copy()
    data[FUZZ_FIELD] = payload

    start = time.time()
    try:
        response = session.post(TARGET_URL, data=data, timeout=10)
    except requests.exceptions.Timeout:
        return None, True, 10.0  # timeout = possible time-based SQLi
    elapsed = time.time() - start

    return response, False, elapsed

# ─── MAIN SCANNER ─────────────────────────────────────
def run_scanner():
    payloads = load_payloads(PAYLOAD_FILE)
    session = requests.Session()

    # Grab a baseline response (no injection)
    print("[*] Getting baseline response...")
    baseline, _, _ = send_payload(session, "normaluser")
    baseline_len = len(baseline.text) if baseline else 0
    print(f"[*] Baseline response length: {baseline_len} chars")
    print(f"[*] Starting scan on: {TARGET_URL}")
    print(f"[*] Fuzzing field: {FUZZ_FIELD}")
    print(f"[*] Loaded {len(payloads)} payloads\n")

    findings = []

    for i, payload in enumerate(payloads, 1):
        response, timed_out, elapsed = send_payload(session, payload)

        result = {
            "payload": payload,
            "status": None,
            "length": None,
            "elapsed": round(elapsed, 2),
            "trigger": None
        }

        if timed_out:
            result["trigger"] = "TIME-BASED (request timed out)"
            print(f"[!!!] POSSIBLE TIME-BASED SQLi: {payload}")
            findings.append(result)
            continue

        result["status"] = response.status_code
        result["length"] = len(response.text)

        # Error-based detection
        error = detect_error(response.text)
        if error:
            result["trigger"] = f"ERROR-BASED: matched '{error}'"
            print(f"[!!!] ERROR DETECTED | payload: {payload} | matched: {error}")
            findings.append(result)
            continue

        # Time-based detection (if response took 5+ seconds)
        if elapsed >= 5:
            result["trigger"] = f"TIME-BASED (delay: {elapsed}s)"
            print(f"[!!!] TIME DELAY DETECTED | payload: {payload} | delay: {elapsed}s")
            findings.append(result)
            continue

        # Boolean-based hint (response length differs significantly from baseline)
        if abs(result["length"] - baseline_len) > 50:
            result["trigger"] = f"BOOLEAN-HINT (len diff: {abs(result['length'] - baseline_len)})"
            print(f"[?] Length diff | payload: {payload} | len: {result['length']} vs baseline: {baseline_len}")
            findings.append(result)
            continue

        print(f"[{i}/{len(payloads)}] Clean | {payload[:30]:<30} | status: {response.status_code} | len: {result['length']} | time: {elapsed}s")

    # ─── REPORT ───────────────────────────────────────
    print(f"\n[*] Scan complete. {len(findings)} finding(s).")
    with open(REPORT_FILE, "w") as f:
        f.write(f"SQLi Scan Report\nTarget: {TARGET_URL}\nField: {FUZZ_FIELD}\n\n")
        if findings:
            for r in findings:
                f.write(f"[!] Payload: {r['payload']}\n")
                f.write(f"    Trigger: {r['trigger']}\n")
                f.write(f"    Status: {r['status']} | Len: {r['length']} | Time: {r['elapsed']}s\n\n")
        else:
            f.write("No findings detected.\n")
    print(f"[*] Report saved to {REPORT_FILE}")

# ─── RUN ──────────────────────────────────────────────
if __name__ == "__main__":
    run_scanner()