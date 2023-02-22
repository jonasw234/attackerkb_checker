#!/usr/bin/env python3
"""Checks a single CVE or a list of CVEs against AttackerKB
(https://attackerkb.com/) and optionally the National Vulnerability Database
(https://nvd.nist.gov/)

Usage:
attackerkb_checker.py [--nvd] [--apikey=<str>] INPUT

Options:
    -a <str>, --apikey=<str>  The API key for AttackerKB
    --nvd                     Query National Vulnerability Database (NVD) for CVS base score and CVSS vector string. Slower due to rate limiting [default: False]
    INPUT                     Input can be either CVE number or list with one CVE entry per line
"""
import json
import os
import re
import time

from colors import black
from docopt import docopt
import requests


def main(
    arg: str,
    api_key: str,
    nvd: bool = False,
):
    """Prepare list of CVEs to lookup and check them.

    Params
    ------
    arg : str
        The single CVE or list of CVEs (one per line)
    api_key : str
        API key for AttackerKB
    nvd : bool
        Whether to query the NVD as well
    """
    cves = []
    if os.path.isfile(arg):
        with open(arg, "r", encoding="utf8") as file:
            for line in file:
                cve_search = re.search(r"cve-\d{4}-\d+", line, re.IGNORECASE)
                if cve_search:
                    cves.append(cve_search.group(0).lower())
    else:
        cves.append(arg.lower())
    for idx, cve in enumerate(cves):
        check_attackerkb(cve, api_key)
        if idx < len(cves) - 1:
            # Prevent 403s for doing too many requests per second
            time.sleep(0.5)
        if nvd:
            check_nvd(cve)
            if idx < len(cves) - 1:
                # Prevent 403s for doing too many requests per second
                # 5 requests in rolling 30 second window for NVD: https://nvd.nist.gov/developers/start-here
                time.sleep(
                    5.5
                )  # Plus 0.5 seconds from above makes 30 / 5 = 6 seconds delay between requests


def check_attackerkb(cve: str, api_key: str):
    """Checks a CVE against the AttackerKB.

    Params
    ------
    cve : str
        The CVE to check
    api_key : str
        The API key for the AttackerKB
    """
    attackerkb_response = requests.get(
        f"https://api.attackerkb.com/v1/topics/{cve.lower()}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {api_key}",
        },
    )
    if attackerkb_response.status_code != 200:
        print(
            black(
                f"Currently unable to query https://attackerkb.com/topics/{cve.lower()}! Received status code {attackerkb_response.status_code}.",
                bg="cyan",
            )
        )
        return
    attackerkb_response = json.loads(attackerkb_response).text.get("data", {}).get("score", {})
    attacker_value = attackerkb_response.get("attackerValue")
    exploitability = attackerkb_response.get("exploitability")
    if attacker_value or exploitability:
        print(f"AttackerKB has information about {cve.upper()}! https://attackerkb.com/topics/{cve.lower()}")
        if attacker_value:
            background_color = None
            if attacker_value >= 4:
                background_color = "dark red"
            elif attacker_value == 3:
                background_color = "red"
            elif attacker_value >= 2:
                background_color = "yellow"
            else:
                background_color = "green"
            print(
                black(
                    f"Attacker value: {attacker_value}",
                    bg=background_color,
                )
            )
        if exploitability:
            background_color = None
            if exploitability >= 4:
                background_color = "dark red"
            elif attacker_value == 3:
                background_color = "red"
            elif exploitability >= 2:
                background_color = "yellow"
            else:
                background_color = "green"
            print(
                black(
                    f"Exploitability: {exploitability}",
                    bg=background_color,
                )
            )
    else:
        print(
            black(
                "AttackerKB doesn’t have attacker value or exploitability information about "
                f"{cve.upper()}",
                bg="cyan",
            )
        )


def check_nvd(cve: str):
    """Checks a CVE against the NVD.

    Params
    ------
    cve : str
        The CVE to check
    """
    nvd_response = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.upper()}"
    )
    if nvd_response.status_code != 200:
        print(
            black(
                f"Currently unable to query https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.upper()}! Received status code {nvd_response.status_code}.",
                bg="cyan",
            )
        )
        return
    nvd_response = json.loads(nvd_response.text)["vulnerabilities"][0]["cve"]["metrics"]
    try:
        base_score = nvd_response.get(
            "cvssMetricV31",
            nvd_response.get("cvssMetricV30", nvd_response.get("cvssMetricV2")),
        )[0]["cvssData"]["baseScore"]
        vector_string = nvd_response.get(
            "cvssMetricV31",
            nvd_response.get("cvssMetricV30", nvd_response.get("cvssMetricV2")),
        )[0]["cvssData"]["vectorString"]
        background_color = None
        if base_score >= 9:
            background_color = "dark red"
        elif base_score >= 7:
            background_color = "red"
        elif base_score >= 4:
            background_color = "yellow"
        elif base_score >= 0.1:
            background_color = "green"
        print(
            black(
                f"CVS base score: {base_score}: https://nvd.nist.gov/vuln/detail/{cve.upper()}",
                bg=background_color,
            )
        )
        print(f"CVSS vector string: {vector_string}")
    except KeyError:
        print("Querying NVD yielded no results.")


def read_stored_arguments(path: str) -> dict:
    """Reads stored arguments from a configuration file.

    Params
    ------
    path : str
        Path to the config file

    Returns
    -------
    dict
        Default parameters stored in a configuration file
    """
    config = {}
    try:
        with open(path, "r", encoding="utf8") as configfile:
            for line in configfile:
                if "=" in line:
                    config[line.split("=")[0]] = line.split("=")[1].rstrip()
                else:
                    config[line.rstrip()] = True
    except FileNotFoundError:
        print(f"Did you know you can store your settings inside file stored in `{path}` by providing the arguments in the long form one per line?")
    return config

if __name__ == "__main__":
    arguments = docopt(__doc__)
    arguments.update(read_stored_arguments(os.path.join(os.path.dirname(__file__), ".attackerkb_checker")))
    main(arguments["INPUT"], arguments["--apikey"], nvd=arguments["--nvd"])
