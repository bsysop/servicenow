# ServiceNow Widget-Simple-List Misconfiguration Scanner

## Overview
This tool scans for misconfigurations in the **ServiceNow** **widget-simple-list** plugin. It checks whether the target instance is vulnerable to data exposure risks due to misconfigured settings.

## Important Note
For an in-depth understanding of the attack technique and exploitation, consult the [technical details available here](https://www.enumerated.ie/servicenow-data-exposure).

## Pre-requisites
- Python 3.x
- Required Python libraries: `requests`

You can install the required libraries using pip:
```bash
pip install requests
```

## Usage

1. Clone the repository to your local machine.
2. Navigate to the directory containing `servicescan.py`.
3. Choose one of the following methods to run the script using Python 3:

### Method 1: Single URL
```bash
python3 servicescan.py --url https://redacted.service-now.com
```

### Method 2: Multiple URLs from a File
```bash
python3 servicescan.py --file urls.txt
```

### Fast-Check Option
Perform a fast check that only scans for the table `kb_knowledge` using the `--fast-check` argument:
```bash
python3 servicescan.py --url https://redacted.service-now.com --fast-check
```

### Using a Proxy
To use a proxy server, use the `--proxy` option:
```bash
python3 servicescan.py --url https://redacted.service-now.com --proxy http://host:port
```

### Example Output
If the target instance is found to be vulnerable, you'll receive an output similar to the following:
```bash
https://redacted.service-now.com/api/now/sp/widget/widget-simple-list?t=incident is EXPOSED, found at least 167 items
https://redacted.service-now.com/api/now/sp/widget/widget-simple-list?t=oauth_entity is EXPOSED, found at least 3 items
Headers to forge requests:
X-UserToken: 76a458ffdbf5[REDACTED]0c02ba13393b764
Cookie: JSESSIONID=7EB7[REDACTED]B5D07E; glide_user_route=glide.4884750d[REDACTED]ca0436e4; glide_node_id_for_js=3143935013eaa5a1e[REDACTED]8a698b419c40837dfce63002d5;
```

> **Note:** A table may be public but not necessarily expose sensitive information. Always verify that the disclosed data is indeed confidential before taking any action.

## Credits and Contributors

- [Aaron Costello](https://twitter.com/ConspiracyProof) - Researcher who provided the technical details and exploitation method. [Website](https://www.enumerated.ie/)
- [bsysop](https://twitter.com/bsysop) - Tool Creator
- [Aaron Ringo](https://twitter.com/AlphaRingo) - Code Refactor and implementation of --proxy and --file implementations
- [Nathan Sanders](https://github.com/pysanders) - Filtering improvement to detect accurate leaking data
- [Daniel Müller](https://github.com/chdanielmueller) - Implemented requests without the `X-UserToken` header.

## Disclaimer
This tool is intended for educational and ethical testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.
