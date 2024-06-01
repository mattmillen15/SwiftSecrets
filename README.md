# SwiftSecrets
Multi-threaded wrapper for Impacket's Secretsdump.py tool, optimizing rapid and efficient secrets extraction.
___

This script was intended to be used to streamline domain-wide audits of locally stored credentials. For auditing Service Account Credentials in Plaintext and Local Administrator Credential Reuse -- see it's sister [DumpInspector](https://github.com/mattmillen15/DumpInspector).

This script will:
- Take a list of hostnames as input. This is the true intention as client's want hostnames, not IP addresses, when reporting identified vulnerabilities.
- Warns the user about potential for account lockout risks and device quarantine before starting.
- Use a quick NMAP check to find live hosts in that list as to prevent delays due to unreachable hosts.
- Perform multi-threaded execution of Impacket's Secretsdump.py tool using Python's concurrent.futures.ThreadPoolExecutor for efficiency.
- Provides a progress bar to monitor the execution status in real time.
- Log detailed execution output and errors to a file for later review.
- Output results to a specified directory, with a default option if none is provided.
___

# Usage:
**Do I really need to say be careful.....? Before running a mass secretsdump be sure that their EDR isn't going to quarantine these hosts.....*

```zsh
SwiftSecrets.py -tf <TARGET_FILE< -d <DOMAIN> -u <USERNAME> -p <PASSWORD? [-o OUTPUT]
```
___
