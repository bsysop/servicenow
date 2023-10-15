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

### Example Output
If the target instance is found to be vulnerable, you'll receive an output similar to the following:

```bash
https://company.service-now.com is VULNERABLE, it was found at least 500 items
```

## Credits

- [Aaron Costello](https://twitter.com/ConspiracyProof) - Researcher who provided the technical details and exploitation method. [Website](https://www.enumerated.ie/)

## Disclaimer
This tool is intended for educational and ethical testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
