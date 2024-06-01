# SwiftSecrets
Multi-threaded wrapper for Impacket's Secretsdump.py tool, optimizing rapid and efficient secrets extraction.

This script was intended to be used to streamline domain-wide audits of locally stored credentials. See it's sister [DumpInspector](https://github.com/mattmillen15/DumpInspector).  
___

# Usage:
- **Do I really need to say be careful.....? Before running a mass secretsdump be sure that their EDR isn't going to quarantine these hosts.....*
```zsh
DumpInspector.py -d <path-to-secretsdump-folder> [-o OUTPUT]
```
___
