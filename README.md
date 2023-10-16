# ServiceNow Widget-Simple-List Misconfiguration Scanner

## Overview
This tool scans for misconfigurations in the **ServiceNow** **widget-simple-list** plugin. It checks whether the target instance is vulnerable to data exposure risks due to misconfigured settings.

## Important Note
For an in-depth understanding of the attack technique and exploitation, consult the [technical details available here](https://www.enumerated.ie/servicenow-data-exposure).

## Pre-requisites
- Python 3.x
- Required Python libraries: `requests`, `BeautifulSoup`

You can install the required libraries using pip:
```bash
pip install requests beautifulsoup4
```

## Usage

1. Clone the repository to your local machine.
2. Navigate to the directory containing `servicescan.py`.
3. Run the script using Python 3 as shown below:

    ```bash
    > python3 servicescan.py --url https://company.service-now.com
    ```

### Fast-Check Option
You can perform a fast check that only scans for the table `incident` using the `--fast-check` argument:

    ```bash
    > python3 servicescan.py --url https://company.service-now.com --fast-check
    ```

### Example Output
If the target instance is found to be vulnerable, you'll receive an output similar to the following:

```bash
https://hackerone.service-now.com/api/now/sp/widget/widget-simple-list?t=sc_cat_item is EXPOSED, found at least 167 items
```

> **Note:** A table may be public but not necessarily expose sensitive information. Always verify that the disclosed data is indeed confidential before taking any action.

## Credits

- [Aaron Costello](https://twitter.com/ConspiracyProof) - Researcher who provided the technical details and exploitation method. [Website](https://www.enumerated.ie/)

## Disclaimer
This tool is intended for educational and ethical testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
