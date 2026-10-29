# FRIS — Firmware Risk Intelligence System
### Powered by Blockchain and AI Agents

A beginner-friendly, interactive cybersecurity-themed web prototype built with Flask, HTML, CSS, and JavaScript.

## What works in this starter

- Responsive cyber-themed dashboard
- Firmware file upload (maximum 50 MB)
- File extension validation
- SHA-256 fingerprint calculation
- Basic printable-string extraction
- Low-confidence component hints for selected common software names
- Three structured AI-agent workflow placeholders
- Illustrative demo score (not CVSS and not a verified risk rating)
- JSON report export
- Local hash-chain audit log and record-link display

## What is NOT implemented yet

- No actual AI model calls
- No live NVD vulnerability matching
- No complete firmware unpacking or reverse engineering
- No real public/private blockchain deployment
- No claim that an uploaded firmware file is safe or unsafe

The UI labels these limitations intentionally. A hash chain saved in a local JSON file is only a learning demo, not a blockchain and not strong protection against a privileged user rewriting the file.

## Requirements

- Python 3.10 or newer
- Git (optional, for GitHub)
- A modern browser

## Run locally (Windows)

1. Download and extract this project ZIP.
2. Open the extracted `FRIS_Firmware_Security_Platform` folder.
3. Open Command Prompt or PowerShell in that folder.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt:

   ```bat
   .venv\Scripts\activate.bat
   ```

5. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

6. Start the website:

   ```bash
   python app.py
   ```

7. Open this address in your browser:

   `http://127.0.0.1:5000`

Keep the terminal running while you use the website. Press `Ctrl+C` to stop it.

## Test it

Use a firmware file you own or have permission to analyze. You can also create a small harmless text file with a supported extension, for example `sample.bin`, containing:
```
Linux version 5.10.0
OpenSSL 1.1.1
BusyBox 1.35.0
```
This only tests the demo's string matching; it is not a real firmware image.

## GitHub: upload your project

1. Sign in to GitHub and create a new repository named `FRIS-Firmware-Risk-Intelligence-System`.
2. Keep it public only if you are comfortable sharing the code. Never upload confidential firmware, API keys, passwords, or real customer scan data.
3. Extract this ZIP.
4. In the repository page, choose **Add file → Upload files** and upload the project files/folders, or use Git from the project folder:

   ```bash
   git init
   git add .
   git commit -m "Initial FRIS prototype"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/FRIS-Firmware-Risk-Intelligence-System.git
   git push -u origin main
   ```

   Replace `YOUR-USERNAME` with your GitHub username.

## Can GitHub make this website live?

GitHub stores the code, but GitHub Pages only hosts static sites. This project uses Flask for uploads and processing, so it needs a Python-capable host to run as a web application. You can first run it locally, then deploy the Flask app to a suitable Python hosting provider. Review its storage, privacy, and free-tier limits before uploading any firmware.

For a classroom demo, keep it local. Do not expose a file-upload endpoint to the public internet without stronger isolation, authentication, rate limits, file scanning, and production security review.

## Suggested next development steps

1. Integrate a real firmware extraction tool in an isolated worker.
2. Add NVD API lookups with exact product/version matching and source references.
3. Implement agent workflows with explicit evidence and validation.
4. Add comparison of two firmware versions for patch verification.
5. Replace the local hash-chain demo with a tested smart contract on a local development network.
6. Add tests, authentication, safe storage, audit-log verification, and deployment hardening.

## Architecture

Browser UI → Flask API → file hashing/string extraction → component hints → agent workflow placeholders → local audit hash chain → report.

**Project title:** FRIS — Firmware Risk Intelligence System — Powered by Blockchain and AI Agents.
