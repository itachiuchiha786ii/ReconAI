import subprocess
import re
import os
from datetime import datetime
from html import escape
from termcolor import cprint

# ==== SETUP ====
TARGET = input("Enter target domain/IP: ").strip()
DATE = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
REPORT_DIR = "reports"
RESULTS_DIR = "results"
TEMPLATE_PATH = "template/report_template.html"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ==== TOOLS TO RUN ====
tools = {
    "WHOIS": f"whois {TARGET}",
    "NSLOOKUP": f"nslookup {TARGET}",
    "DIG": f"dig {TARGET}",
    "TRACEROUTE": f"traceroute {TARGET}",
    "DNSRECON": f"dnsrecon -d {TARGET}",
    "NMAP": f"nmap -A -T4 {TARGET}",
    "WHATWEB": f"whatweb {TARGET}",
    "WAFW00F": f"wafw00f {TARGET}",
    "NUCLEI": f"nuclei -u http://{TARGET}",
    "SSLScan": f"sslscan {TARGET}"
}

results = {}

cprint(f"\n[+] Starting recon on: {TARGET}\n", "green")

# ==== RUN RECON TOOLS ====
for name, cmd in tools.items():
    cprint(f"[*] Running: {name}", "yellow")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=300).decode()
    except subprocess.CalledProcessError as e:
        output = f"Error running {name}:\n{e.output.decode()}"
    except Exception as e:
        output = f"Unexpected error running {name}:\n{str(e)}"
    results[name] = output

# ==== SAVE RAW TEXT OUTPUT ====
raw_output_file = f"{RESULTS_DIR}/raw_output_{DATE}.txt"
with open(raw_output_file, "w") as f:
    for name, output in results.items():
        f.write(f"\n\n===== {name} =====\n{output}\n")

# ==== LOAD HTML TEMPLATE ====
report_path = f"{REPORT_DIR}/recon_report_{TARGET.replace('.', '')}_{DATE}.html"
try:
    with open(TEMPLATE_PATH) as t:
        template = t.read()
except FileNotFoundError:
    cprint(f"[-] HTML template not found at {TEMPLATE_PATH}", "red")
    exit(1)

# ==== INJECT RAW TOOL OUTPUT ====
for section, output in results.items():
    safe_output = escape(output)
    template = template.replace(f"{{{{{section}}}}}", f"<pre>{safe_output}</pre>")

# ==== SGPT AI ANALYSIS ====
def run_sgpt_with_cat(filepath, prompt):
    try:
        command = f'cat "{filepath}" | sgpt --model provider-2/gpt-3.5-turbo "{prompt}"'
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=120)
        if result.returncode != 0:
            return f"[SGPT Error: {result.stderr.strip()}]"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[SGPT timeout]"
    except Exception as e:
        return f"[SGPT Error: {str(e)}]"

# ==== AI PROMPT ====
prompt = (
    "You are a CEH (Certified Ethical Hacker) AI assistant helping a professional with advanced reconnaissance analysis. Analyze the following structured recon output from a penetration test. Break down the findings clearly, identify potential vulnerabilities, misconfigurations, or interesting behaviors, and suggest exploit paths where applicable.The recon tools used include.1. WHOIS – Domain ownership and registrar information.2. NSLOOKUP – DNS record resolution data.3. DIG – DNS zone details and records.4. TRACEROUTE – Network path to the target.5. DNSRECON – Detailed DNS enumeration and discovery.6. NMAP – Port scan and service enumeration.7. SSLSCAN – SSL/TLS certificate data, weak ciphers, protocol versions.8. NUCLEI – Vulnerability scanning using predefined templates (CVEs, misconfigurations, exposures).Your task:- Summarize important security findings per tool.- Identify publicly exposed services and versions (from NMAP).- Detect insecure SSL protocols or cipher suites (from SSLSCAN).- Extract any confirmed or potential vulnerabilities from Nuclei results.- Highlight DNS misconfigurations or data leakage (from DIG/DNSRECON).- Suggest next steps or possible exploits based on findings (e.g., CVE exploits, brute force, subdomain takeovers).- Focus on actionable insights, red-team-style thinking, and OSINT, \n\n Respond clearly using the following format:\n === Summary ===\n...\n\n=== Sensitive Findings ===\n...\n\n=== Recommendations ===\n... Important: Use structured reasoning and make inferences like a real penetration tester. You are assisting a human hacker, not a general user. Be sharp, technical, and suggest realistic next steps."
)

# ==== RUN AI ANALYSIS ====
cprint("[*] Running SGPT combined AI analysis...", "yellow")
ai_response = run_sgpt_with_cat(raw_output_file, prompt)

# ==== PARSE AI RESPONSE ====
def extract_section(text, section_name):
    lines = text.splitlines()
    normalized_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.upper() in ["EXECUTIVE SUMMARY", "SENSITIVE FINDINGS", "RECOMMENDATIONS"]:
            normalized_lines.append(f"## {stripped.upper()}")
        else:
            normalized_lines.append(line)
    normalized_text = "\n".join(normalized_lines)

    pattern = rf"## {section_name.upper()}\n+((?:.|\n)*?)(?=\n## [A-Z ]+|\Z)"
    match = re.search(pattern, normalized_text, re.IGNORECASE)
    return match.group(1).strip() if match else "[Section missing]"

summary = extract_section(ai_response, "Executive Summary")
sensitive = extract_section(ai_response, "Sensitive Findings")
recommendations = extract_section(ai_response, "Recommendations")
template = template.replace("{{TARGET}}", TARGET)
template = template.replace("{{DATE}}", DATE)
# ==== Inject AI analysis sections ====
template = template.replace("{{summary}}", f"<pre>{escape(summary)}</pre>")
template = template.replace("{{sensitive}}", f"<pre>{escape(sensitive)}</pre>")
template = template.replace("{{recommendations}}", f"<pre>{escape(recommendations)}</pre>")

# ==== SAVE FINAL HTML REPORT ====
with open(report_path, "w") as out:
    out.write(template)

# ==== DONE ====
cprint(f"\n[+] Recon completed.", "green")
cprint(f"[+] Raw output saved to: {raw_output_file}", "cyan")
cprint(f"[+] HTML report generated at: {report_path}", "cyan")
cprint(f"\n[*] Full SGPT Raw Output:\n", "magenta")
print(ai_response)
