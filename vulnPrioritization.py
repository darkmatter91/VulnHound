import subprocess
import pyfiglet
import json


# This script is designed to take a CVE and determine the risk level of the vulnerability based on the CVSS score, age of the vulnerability, EPSS score, and exposure level.
def banner():
    banner = pyfiglet.figlet_format("VulnHound")
    print(banner)


def get_user_input():
    vuln_cve = input("[!]Enter CVE: ").upper()
    vuln_exposure = input("[!]Vulnerability Exposure (External/Internal/E/I): ")
    if vuln_exposure.lower() not in ['external', 'internal', 'e', 'i']:
        print("Invalid input. Please enter 'External', 'Internal', 'E', or 'I'.")
        vuln_exposure = input("Vulnerability Exposure (External/Internal/E/I): ")
    return vuln_cve, vuln_exposure


def parse_vulnerability(vuln_cve):
    vuln_info = subprocess.run(["cvemap.exe", "-json", "-id", vuln_cve], capture_output=True, text=True, encoding="utf-8")
    vuln_data = json.loads(vuln_info.stdout)
    for item in vuln_data:
        if item['cve_id'] == vuln_cve:
            cve_id = item.get('cve_id')
            cve_desc = item.get('cve_description')
            cvss_score = item.get('cvss_score')
            age_in_days = item.get('age_in_days')
            cve_desc = cve_desc.replace("\n", " ")
            epss_score = item.get('epss', {}).get('epss_score')
            is_exploited = item.get('is_exploited')
            kev_status = item.get('kev_status')
            kev_added_date = item.get('kev', {}).get('added_date')
    return cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_status, kev_added_date


def rank_vulnerability(cvss_score, age_in_days, epss_score, vuln_exposure, kev_added_date):
    age_in_days_modifier = 1 if age_in_days > 365 else 0
    epss_score_modifier = -1 if epss_score <= 0.20 else 0
    exposure_modifier = -2 if vuln_exposure.lower() == 'internal' or vuln_exposure.lower() == 'i' else 0
    kev_modifier = 2 if kev_added_date else 0
    risk_score = cvss_score + age_in_days_modifier + epss_score_modifier + exposure_modifier + kev_modifier
    if risk_score <= 3.99:
        risk_level = "Low"
    elif risk_score >= 4 and risk_score <= 6.99:
        risk_level = "Medium"
    elif risk_score >= 7 and risk_score <= 8.99:
        risk_level = "High"
    elif risk_score >= 9:
        risk_level = "Critical"
    else:
        risk_level = "Unknown"
    return risk_score, risk_level

def write_to_csv(cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_status, kev_added_date, risk_score, risk_level):
    with open('vulnerabilities.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE ID', 'CVE Description', 'CVSS Score', 'Age in Days', 'EPSS Score', 'Is Exploited', 'KEV Status', 'KEV Added Date', 'Risk Score', 'Risk Level'])
        writer.writerow([cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_status, kev_added_date, risk_score, risk_level])

    
def main():
    banner()
    print("[-]Updating CVE Map...")
    subprocess.run(["cvemap.exe", "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[!]CVE Map Updated")
    vuln_cve, vuln_exposure = get_user_input()
    print("[!]Retrieving Vulnerability Information...")
    print("")
    cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_status, kev_added_date = parse_vulnerability(vuln_cve)
    print(f"[+]CVE ID: {cve_id}")
    print(f"[+]CVE Description: {cve_desc}")
    print(f"[+]CVSS Score: {cvss_score}")
    print(f"[+]EPSS Score: {epss_score}")
    print(f"[+]Is Exploited: {is_exploited}")
    print(f"[+]KEV Added Date: {kev_added_date}")
    
    print("")
    print("[!] Calculating Vulnerability Priority...")
    risk_score, risk_level = rank_vulnerability(cvss_score, age_in_days, epss_score, vuln_exposure, kev_added_date)
    print(f"[+]Risk Score: {risk_score}")
    print(f"[+]Risk Level: {risk_level}")
    

if __name__ == "__main__":
    main()
