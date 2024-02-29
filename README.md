# VulnHound Risk Calculator

VulnHound Risk Calculator is a Python script designed to take a CVE (Common Vulnerabilities and Exposures) and determine the risk level of the vulnerability based on the CVSS (Common Vulnerability Scoring System) score, age of the vulnerability, EPSS (Exploit Prediction Scoring System) score, and exposure level.

![image](https://github.com/darkmatter91/VulnHoundRiskCalculator/blob/main/assets/toolLogo.png)



### Prerequisites

Before running the script, you must install and configure `cvemap` by ProjectDiscovery. You can find the installation instructions [here](https://github.com/projectdiscovery/cvemap).

### Functions

- `banner()`: This function prints the banner for the script using the pyfiglet library.

- `get_user_input()`: This function prompts the user to input the CVE and the exposure level of the vulnerability. The exposure level can be 'External', 'Internal', 'E', or 'I'.

- `parse_vulnerability(vuln_cve)`: This function takes the CVE as an argument and uses the subprocess library to run the cvemap.exe command with the CVE as an argument. It then parses the JSON output to extract the relevant information about the vulnerability.

- `rank_vulnerability(cvss_score, age_in_days, epss_score, vuln_exposure, kev_added_date)`: This function takes the CVSS score, age of the vulnerability, EPSS score, exposure level, and the date the vulnerability was added to the KEV (Known Exploited Vulnerabilities) list as arguments. It calculates a risk score based on these factors and assigns a risk level to the vulnerability.

- `write_to_csv(cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_status, kev_added_date, risk_score, risk_level)`: This function takes the CVE ID, description, CVSS score, age in days, EPSS score, whether the vulnerability is exploited, KEV status, KEV added date, risk score, and risk level as arguments. It writes these details to a CSV file named 'vulnerabilities.csv'.
  - Example CSV Output: ![image](https://github.com/darkmatter91/VulnHoundRiskCalculator/blob/main/assets/sampleOutput.png)

- `main()`: This is the main function that calls all the other functions. It updates the CVE map, gets user input, retrieves vulnerability information, calculates the vulnerability priority, and writes the details to a CSV file.

### How to Run

To run the script, navigate to the directory containing the script in your terminal and execute the following command:

```bash
python vulnPrioritization.py
```

The script will guide you through the process.

### Disclaimer

This script is for illustrative purposes only. The author is not responsible for the outcome of your decision to prioritize or remediate vulnerabilities based on the output of this script. Always consult with a qualified security professional when making decisions about vulnerability management.


