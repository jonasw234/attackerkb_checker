# attackerkb_checker
Checks a single CVE or a list of CVEs against [AttackerKB](https://attackerkb.com/) and optionally the [National Vulnerability Database](https://nvd.nist.gov/).

# Usage
```bash
attackerkb_checker.py [--nvd] [--apikey=<str>] INPUT

Options:
    -a <str>, --apikey=<str>  The API key for AttackerKB [not used in dev version]
    --nvd                     Query National Vulnerability Database (NVD) for CVS base score and CVSS vector string [default: False]
    INPUT                     Input can be either CVE number or list with one CVE entry per line
```

Example:
```bash
~ » attackerkb_checker.py CVE-2023-0297                                                                                                                         
AttackerKB has information about CVE-2023-0297! https://attackerkb.com/topics/cve-2023-0297
Attacker value: 2
Exploitability: 5
CVS base score: 9.8: https://nvd.nist.gov/vuln/detail/CVE-2023-0297
CVSS vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Files will be searched line by line with a regex to detect CVEs (one per line).

You can store parameters that you want to use everytime (e.g. your AttackerKB API key) in a file called `.attackerkb_checker` right next to the script, one command line parameter in the long form at a time, e.g.:
```
--apikey=INSERTYOURAPIKEYHERE
--nvd
```
Parameters stored in the file will override command line parameters.
