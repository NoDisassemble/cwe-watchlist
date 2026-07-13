# CWE Watch

CWE Watch is a live security intelligence dashboard for exploring software weaknesses from the [MITRE Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) catalog.

The dashboard builds a top-five watchlist using vulnerabilities known to be exploited in the wild. It combines CISA Known Exploited Vulnerabilities (KEV) data with FIRST EPSS likelihood data, then enriches each result with its corresponding MITRE CWE record.

## Features

- Displays the current CWE catalog version and catalog totals
- Ranks five high-priority weaknesses using CISA KEV, ransomware, recency, and EPSS signals
- Shows threat scores and full descriptions for watchlist entries
- Looks up individual weaknesses by CWE number
- Exports the current top-five watchlist as a PDF report
- Supports light and dark themes
- Caches the generated watchlist for 24 hours to reduce external API requests

## Data sources

- [MITRE CWE REST API](https://github.com/CWE-CAPEC/REST-API-wg) for CWE catalog metadata and weakness records
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for evidence of exploitation in the wild
- [FIRST EPSS](https://www.first.org/epss/) for exploit-probability percentiles

An internet connection is required when the server retrieves fresh data. CWE Watch is an informational dashboard; its threat score is a project-specific ranking and should not be treated as an official risk rating.

## Run locally

### Requirements

- Python 3.9 or newer
- A modern web browser
- An internet connection for live API data

No Python packages or JavaScript dependencies need to be installed.

### Start the app

1. Clone the repository and enter its directory:

   ```bash
   git clone https://github.com/NoDisassemble/cwe-watchlist.git
   cd cwe-watchlist
   ```

2. Start the local server:

   ```bash
   python server.py
   ```

   On Windows, if `python` is not recognized, use:

   ```powershell
   py server.py
   ```

3. Open [http://localhost:8000](http://localhost:8000) in your browser.

4. Press `Ctrl+C` in the terminal to stop the server.

Do not open `index.html` directly. The Python server is required because it serves the site and proxies requests to the external APIs.

## Project structure

```text
cwe-watchlist/
|-- index.html    # Dashboard markup
|-- styles.css    # Layout, responsive styles, and themes
|-- script.js     # Dashboard rendering, lookup, and PDF export
|-- server.py     # Static server, API proxy, ranking, and cache
`-- README.md
```

## Troubleshooting

- **The dashboard says data is unavailable:** Confirm that the computer can reach the MITRE, CISA, and FIRST APIs, then select **Refresh data**.
- **Port 8000 is already in use:** Stop the other process using that port, or change `8000` near the bottom of `server.py` and open the matching URL.
- **The data appears stale:** Delete `.watchlist-cache.json` and restart the server to force a fresh watchlist calculation.

## License

No license has been specified for this project yet.
