# Extract Publisher Certificates from Signed Executables

This PowerShell script helps you extract trusted publisher certificates from digitally signed `.exe` or `.msi` files. The exported `.cer` files can be used to configure:

- **AppLocker** rules using *Signed Publisher* conditions
- **Microsoft Defender for Endpoint (MDE)** indicators for *SPC-based* (Signed Publisher Certificate) allow or block rules

---

## Features

- Prompts for a folder (defaults to the script's location)
- Lists all `.exe` and `.msi` files in the folder
- Allows selection of individual files or all files at once
- Extracts the signing certificate from validly signed files
- Saves the certificate(s) in the same directory as the file(s), with a `.cer` extension

---

## Usage

1. Place the script in the same folder as the executables you wish to extract certificates from.
2. Locate the script in PowerShell then run: .\ps-spc-extractor.ps1
3. When prompted, hit Enter for script's folder otherwise choose other location.
4. The script will list the available executables, chose one or all.
5. Once selection is made, the script will issue certificates in CER format in the same directory as the source.
