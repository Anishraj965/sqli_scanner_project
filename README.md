# Evil SQLi Scanner

A comprehensive SQL injection (SQLi) vulnerability scanner designed for ethical penetration testing and security research. It supports multiple detection techniques, DBMS fingerprinting, and automated data extraction.

---

## Features

### Detection Techniques
- **Boolean-Based** — Detects SQLi by analyzing differences in page responses between TRUE and FALSE conditions
- **Time-Based** — Detects SQLi using time delays (e.g., `SLEEP()`, `pg_sleep()`)
- **Error-Based** — Detects SQLi by triggering and parsing database error messages
- **Union-Based** — Detects SQLi using `UNION SELECT` payload reflection

### DBMS Detection
The scanner fingerprints the database engine using signature-based analysis:
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server (MSSQL)
- Oracle
- SQLite

### DVWA Lab Integration
Built-in support for [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA) authentication and session management for safe, controlled testing:
```bash
python main.py -u 'http://localhost/dvwa/vulnerabilities/sqli/?id=1' --dvwa-login
```

### Automated Exploitation
Once a vulnerability is confirmed, the tool can extract:
- **Database Version** (`@@version`, `version()`, etc.)
- **Current Database User** (`user()`, `current_user`, etc.)

### Additional Capabilities
- **Web Crawler** — Automatically discovers endpoints with query parameters
- **WAF Detection** — Identifies blocked requests and WAF responses
- **Boolean Hints Auto-Discovery** — Learns true/false page indicators automatically
- **Retry Logic with Backoff** — Resilient HTTP client for unstable targets
- **Verbose & Debug Logging** — Detailed output for troubleshooting

---

## Installation

### Prerequisites
- Python 3.8+
- `pip` package manager

### Step 1: Clone the Repository
```bash
git clone https://github.com/Anishraj965/sqli_scanner_project.git
cd sqli_scanner_project
```

### Step 2: Install Dependencies
```bash
python -m pip install -r requirements.txt
```

> **Dependencies include:** `requests`, `beautifulsoup4`, `pyfiglet` (optional, for banner)

---

## Usage

### Basic Scan
```bash
python main.py -u 'http://target.com/page.php?id=1'
```

### Scan with Specific Techniques
```bash
python main.py -u 'http://target.com/page.php?id=1' --techniques EU
# Or use full names:
python main.py -u 'http://target.com/page.php?id=1' --techniques error,union
```

### Force DBMS and Adjust Timing
```bash
python main.py -u 'http://target.com/page.php?id=1' --dbms MySQL --time-delay 3
```

### DVWA Testing with Auto-Login
```bash
python main.py -u 'http://localhost/dvwa/vulnerabilities/sqli/?id=1' --dvwa-login
```

### Boolean-Based Scan with Custom Keywords
```bash
python main.py -u 'http://target.com/page.php?id=1' --techniques B \
  --true-keyword "Welcome" --false-keyword "Not Found"
```

### Crawl-Only Mode (Discovery)
```bash
python main.py -u 'http://target.com/' --mode crawl --depth 3
```

### Full Command Reference
```bash
python main.py --help
```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | **Required.** Target URL to scan |
| `--mode` | `crawl` (discover only) or `scan` (discover + test) — default: `scan` |
| `--depth` | Crawl depth for link discovery — default: `2` |
| `--delay` | Delay between requests (seconds) — default: `0.5` |
| `--timeout` | HTTP request timeout (seconds) — default: `20` |
| `--retries` | Number of retries on failure — default: `5` |
| `--no-cookies` | Disable session cookie persistence |
| `--verbose` | Enable verbose logging |
| `--debug` | Enable debug-level output |
| `--dvwa-login` | Auto-login to DVWA (admin/password) |
| `-c, --column` | Manually specify UNION column count |
| `--techniques` | Techniques to use: `B`/`boolean`, `E`/`error`, `U`/`union`, `T`/`time` |
| `--dbms` | Force DBMS: `MySQL`, `PostgreSQL`, `MSSQL`, `Oracle`, `SQLite` |
| `--time-delay` | Sleep delay for time-based tests (seconds) — default: `5` |
| `--true-keyword` | Keyword indicating a TRUE condition (repeatable) |
| `--false-keyword` | Keyword indicating a FALSE condition (repeatable) |

---

## Project Structure

```
sqli_scanner_project/
├── main.py        # Entry point — CLI banner and argument parsing
├── app.py         # Application orchestrator — crawl/scan workflow
├── core.py        # Core utilities — HTTP client, crawler, signatures, config
├── scanner.py     # Detection engine — SQLi technique implementations
├── exploiter.py   # Data extraction — version/user extraction post-confirmation
└── requirements.txt
```

---

## Output

Results are saved automatically in a domain-named folder under the project directory:

```
target.com/
├── crawl_result.txt    # Discovered endpoints and parameters
├── scan_result.txt     # Human-readable findings summary
└── scan_result.json    # Machine-readable structured results
```

A log file `sqli_scanner.log` is also generated for audit trails.

---

## Detection Methodology

1. **Crawling** — Discovers URLs with query parameters up to the specified depth.
2. **Fingerprinting** — Attempts to identify the DBMS via error signatures or forced hints.
3. **Technique Testing** — Runs detection in priority order: **Error → Union → Boolean → Time**.
4. **Confirmation** — Requires multiple confirmations or control comparisons to reduce false positives.
5. **Exploitation** — If confirmed, extracts version and user information using the detected technique.

---

## Ethical Use & Disclaimer

> **This tool is intended for educational and authorized penetration testing purposes only.**
>
> The author is **not responsible** for any misuse of this tool against systems without explicit prior authorization. Unauthorized access to computer systems is illegal under various jurisdictions.
>
> **Use responsibly. Always obtain proper permission before testing.**

---

## License

[MIT License](LICENSE) — See `LICENSE` file for details.

---

## Author

**legendevil849**

For issues, contributions, or feature requests, please open an issue on the [GitHub repository](https://github.com/Anishraj965/sqli_scanner_project).
