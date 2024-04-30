import subprocess
import pyfiglet
import json
import csv
import pandas as pd
import datetime


def banner():
    vulnhound_banner = pyfiglet.figlet_format("VulnHound")
    print(vulnhound_banner)
    print("VulnHound is a tool designed to help security analysts prioritize vulnerabilities based on various criteria.")


def get_user_input():
    """
    Method to get user input for vulnerability information.

    Returns:
        tuple: A tuple containing the vulnerability CVE, exposure, and asset criticality.

    Example:
        >>> get_user_input()
        Enter Vulnerability CVE (CVE-####-####): CVE-2022-1234
        Enter Exposure (Internal/External): internal
        Enter Asset Importance (Low/Medium/High): medium
        ('CVE-2022-1234', 'internal', 'medium')
    """
    vuln_cve = input('Enter Vulnerability CVE (CVE-####-####): ')

    vuln_exposure = None
    while vuln_exposure not in ['internal', 'external']:
        vuln_exposure = input('Enter Exposure (Internal/External): ').lower()
        if vuln_exposure not in ['internal', 'external']:
            print('Invalid input. Please enter "Internal" or "External".')

    asset_criticality = None
    if vuln_exposure == 'internal':
        while asset_criticality not in ['low', 'medium', 'high']:
            asset_criticality = input('Enter Asset Importance (Low/Medium/High): ').lower()
            if asset_criticality not in ['low', 'medium', 'high']:
                print('Invalid input. Importance must be either "Low", "Medium", or "High".')

    # If exposure is external or asset criticality isn't specified, then set it to High (or default)
    if asset_criticality is None:
        asset_criticality = 'high'

    return vuln_cve, vuln_exposure, asset_criticality


def parse_vulnerability(vuln_cve):
    """
    Args:
        vuln_cve: A string representing the CVE (Common Vulnerabilities and Exposures) identifier to be parsed.

    Returns:
        A tuple containing the following information:
        - cve_id: A string representing the CVE ID.
        - cve_desc: A string representing the CVE description.
        - cvss_score: A string representing the CVSS (Common Vulnerability Scoring System) score.
        - age_in_days: An integer representing the age of the CVE in days.
        - epss_score: A string representing the EPSS (Exploit Prediction Scoring System) score.
        - is_exploited: A boolean value indicating if the vulnerability is exploited or not.
        - kev_added_date: A string representing the date when the vulnerability was added to the KEV (Known Exploited Vulnerabilities) list.
    """
    vuln_info = subprocess.run(["cvemap.exe", "-json", "-id", vuln_cve],
                               capture_output=True,
                               text=True,
                               encoding="utf-8")
    vuln_data = json.loads(vuln_info.stdout)
    # If the CVE is not found, print "CVE not found" and exit the program.
    if not vuln_data:
        print(f"[!]CVE {vuln_cve} not found.")
        exit()
    cve_id = cve_desc = cvss_score = age_in_days = epss_score = is_exploited = kev_added_date = None
    for item in vuln_data:
        if item['cve_id'] == vuln_cve:
            cve_id = item.get('cve_id')
            cve_desc = item.get('cve_description')
            cvss_score = item.get('cvss_score')
            if cvss_score is None:
                raise ValueError("CVSS Score not defined for this vulnerability.")
            age_in_days = item.get('age_in_days')
            cve_desc = cve_desc.replace("\n", " ")
            epss_score = item.get('epss', {}).get('epss_score')
            is_exploited = item.get('is_exploited')
            kev_added_date = item.get('kev', {}).get('added_date')
    return cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_added_date


def rank_vulnerability(cvss_score, age_in_days, epss_score, vuln_exposure, asset_criticality, kev_added_date):
    """
    Args:
        cvss_score: The Common Vulnerability Scoring System (CVSS) score of the vulnerability.
        age_in_days: The number of days since the vulnerability was discovered.
        epss_score: The External Prevalence and Severity Score (EPSS) of the vulnerability.
        vuln_exposure: The level of vulnerability exposure.
        asset_criticality: The criticality of the asset.
        kev_added_date: The date when the vulnerability was added to the Key Enterprise Vulnerability (KEV) database.

    Returns:
        risk_score: The calculated risk score based on the provided parameters.
        risk_level: The corresponding risk level based on the calculated risk score.
    """
    with open('setup.json') as f:
        setup = json.load(f)

    if asset_criticality.lower() == 'low':
        asset_criticality_modifier = -2
    elif asset_criticality.lower() == 'medium':
        asset_criticality_modifier = -1
    elif asset_criticality.lower() in ['high', 'external']:
        asset_criticality_modifier = 0
    else:
        asset_criticality_modifier = 0

    epss_score_modifier = setup['epss_weight'] if epss_score >= 0.20 else 0
    age_in_days_modifier = setup['age_in_days'] if age_in_days > 365 else 0
    kev_modifier = setup['kev_weight'] if kev_added_date else 0
    risk_score = cvss_score + age_in_days_modifier + epss_score_modifier + asset_criticality_modifier + kev_modifier

    risk_score = round(min(10, risk_score), 1)

    if risk_score <= 3.99:
        risk_level = "Low"
    elif 4.0 <= risk_score <= 6.99:
        risk_level = "Medium"
    elif 7.0 <= risk_score <= 8.99:
        risk_level = "High"
    elif risk_score >= 9.0:
        risk_level = "Critical"
    else:
        risk_level = "Unknown"

    return risk_score, risk_level


def write_to_csv(cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_added_date, risk_score,
                 risk_level):
    """
    Args:
        cve_id (str): The CVE ID.
        cve_desc (str): The description of the CVE.
        cvss_score (float): The CVSS score.
        age_in_days (int): The age of the CVE in days.
        epss_score (float): The EPSS score.
        is_exploited (bool): Indicates if the CVE is exploited.
        kev_added_date (str): The date when the KEV was added.
        risk_score (float): The risk score.
        risk_level (str): The risk level.

    """
    ranked_date = datetime.datetime.now().strftime("%Y-%m-%d")
    try:
        with open('vulnerabilities.csv', 'r') as file:
            reader = csv.reader(file)
            header = next(reader, None)
    except (FileNotFoundError, StopIteration):
        header = None

    with open('vulnerabilities.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        if header is None:
            writer.writerow(
                ['Ranked Date', 'CVE ID', 'CVE Description', 'CVSS Score', 'Age in Days', 'EPSS Score', 'Is Exploited',
                 'KEV Added Date', 'Risk Score', 'Risk Level'])
        writer.writerow(
            [ranked_date, cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_added_date,
             risk_score, risk_level])


def search_vulnerabilities(search_string):
    """
    Args:
        search_string (str): The string to search for in the vulnerabilities database.

    """
    with open('vulnerabilities.csv', 'r') as file:
        reader = csv.reader(file)
        # First fetch header
        header = next(reader)
        for row in reader:
            if search_string.lower() in [field.lower() for field in row]:
                print(header)  # Print the header
                print(row)  # Print the data row


def scoring_setup():
    """
    Set up weightings for scoring

    This method allows the user to input weightings for different scoring factors and saves them in a json file.

    """
    while True:
        try:
            epss_weight = float(input("Enter weight for EPSS Score (0-2): "))
            if epss_weight < 0 or epss_weight > 2:
                raise ValueError
            age_in_days = float(input("Enter weight for Age of Vulnerability (0-2): "))
            if age_in_days < 0 or age_in_days > 2:
                raise ValueError
            kev_weight = float(input("Enter weight for CISA KEV Importance (0-2): "))
            if kev_weight < 0 or kev_weight > 2:
                raise ValueError
            break
        except ValueError:
            print("Invalid input. Weightings must be numeric values between 0 and 2. Try again.")

    # Then save these values to a json file
    weights = {
        'epss_weight': epss_weight,
        'age_in_days': age_in_days,
        'kev_weight': kev_weight,
    }
    with open('setup.json', 'w') as f:
        json.dump(weights, f)
    print("Weightings have been updated.")


def view_weightings():
    """

    View Weightings

    Prints the metrics and their corresponding weights as specified in the 'setup.json' file.

    Returns:
        None

    Example usage:
        view_weightings()

    """
    with open('setup.json') as f:
        setup = json.load(f)

    print("\n{:<20} {:<10}".format('Metrics', 'Weights'))
    for k, v in setup.items():
        print("{:<20} {:<10}".format(k, v))
    print("\n")


def view_scored_vulnerabilities():
    """

    View Scored Vulnerabilities

    Displays a table of previously scored vulnerabilities.

    Returns:
        None

    Raises:
        FileNotFoundError: If the 'vulnerabilities.csv' file is not found.
        EmptyDataError: If the 'vulnerabilities.csv' file is empty.

    Example:
        view_scored_vulnerabilities()
    """
    try:
        df = pd.read_csv('vulnerabilities.csv')

        pd.set_option('display.max_columns', None)  # Display all columns
        pd.set_option('display.expand_frame_repr', False)  # Avoid line breaks in output
        pd.set_option("display.max_colwidth", 40)  # Maximum column width before text is wrapped
        print("\nPreviously Scored Vulnerabilities:")
        print(df.to_string(index=False))
        print("\n")
    except FileNotFoundError:
        print("File 'vulnerabilities.csv' not found.")
    except pd.errors.EmptyDataError:
        print("File 'vulnerabilities.csv' is empty.")


def menu():
    """
    Display the menu for the vulnerability risk management script.

    The menu displays a list of options for the user to choose from.

    Returns:
        None
    """
    print("\n*******************************")
    print("Vulnerability Risk Management")
    print("*******************************")
    print("""
    Please select an option: 
    NOTE: If this is your first time running the script, you need to run the 'Scoring Setup'
    
    1. Rank a Vulnerability
    2. Scoring Setup
    3. View Weightings
    4. View Scored Vulnerabilities
    5. Exit
    """)


def main():
    """

    Main method used to run the program.

    This method displays a menu of options and allows the user to select an option.
    Based on the user's choice, the program performs different actions.
    It loops continuously until the user chooses to exit.

    Parameters:
        None

    Returns:
        None

    """
    while True:
        menu()
        choice = input("Enter your choice: ")
        print("\n")

        if choice not in ['1', '2', '3', '4', '5']:
            print('>>> Invalid input. Please enter a number between 1 and 5.' + '\n')
            continue

        if choice == '1':
            print('>>> Launching Vulnerability Ranking...')
            vuln_cve, vuln_exposure, asset_criticality = get_user_input()

            try:  # Try to parse vulnerability, and handle exception if raised
                cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_added_date = parse_vulnerability(
                    vuln_cve)
            except ValueError as e:
                print(e)
                continue  # Skip the rest of the loop and prompt for choice again

            risk_score, risk_level = rank_vulnerability(cvss_score, age_in_days, epss_score, vuln_exposure,
                                                        asset_criticality, kev_added_date)
            write_to_csv(cve_id, cve_desc, cvss_score, age_in_days, epss_score, is_exploited, kev_added_date, risk_score
                         ,risk_level)
            print("")
            print('>>> Vulnerability Assessment Details:')
            print(f'>>> CVE ID: {cve_id}')
            print(f'>>> Description: {cve_desc}')
            print(f'>>> CVSS Score: {cvss_score}')
            print(f'>>> Age (in Days): {age_in_days}')
            print(f'>>> EPSS Score: {epss_score}')
            print(f'>>> Is Exploited: {is_exploited}')
            print(f'>>> KEV Added Date: {kev_added_date}')
            print(f'>>> Risk Score: {risk_score}')
            print(f'>>> Risk Level: {risk_level}\n')
        elif choice == '2':
            print('>>> Launching Scoring Setup...')
            scoring_setup()
        elif choice == '3':
            print('>>> Showing Weightings...')
            view_weightings()
        elif choice == '4':
            print('>>> Loading Scored Vulnerabilities...')
            view_scored_vulnerabilities()
        elif choice == '5':
            print('>>> Exiting...')
            break


if __name__ == "__main__":
    banner()
    main()


