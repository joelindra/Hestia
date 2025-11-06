## FTP Login Destroyer 2.0

Rich-powered, high-visibility FTP anonymous-login scanner with a modern live dashboard, event feed, and HTML reporting.

### Highlights
- **Rich TUI**: Live dashboard with animated progress, split layout, and color-coded panels
- **Event Feed**: Real-time log of successes and failures while scanning
- **Parallel Scanning**: Fast execution using a thread pool
- **Smart Stats**: Success rate, current speed, averages, and ETA
- **Reports**: Auto-generated HTML report and a plain list of vulnerable targets

### Demo (TUI)
Add a short screen recording or gif here.

```
┌───────────────── FTP Scan Progress ─────────────────┐
│             Scanning targets... (live)              │
└─────────────────────────────────────────────────────┘
```

### Usage

```bash
python main.py -t 1.2.3.4
python main.py -l targets.txt -w 50 --timeout 4 -o vuln.txt
```

#### Options
- `-t, --target`           Scan a single host (hostname or IP)
- `-l, --list`             Scan a list of hosts (one per line)
- `-w, --workers`          Number of concurrent workers (default: 20)
- `-o, --output`           Output file for vulnerable hosts (default: vuln.txt)
- `--timeout`              Connection timeout in seconds (default: 3)

### Output
- `vuln.txt`: Plaintext list of hosts with anonymous FTP access
- `ftp_scan_report_YYYYMMDD_HHMMSS.html`: Detailed HTML report containing:
  - Stats summary (total, success, failed, success-rate)
  - Successful hosts with server banner, system type, initial directory
  - Sample file listings (first few entries when available)
  - Failed hosts with error reasons

### Features in Detail
- **Live Layout**: Header banner, progress + stats, and a split footer showing current target and a live event log
- **Event Log**: Shows timestamps, host, and colored result (OK/FAIL) as targets complete
- **Improved Progress Bar**: Spinner + bar + M-of-N + elapsed + ETA
- **Graceful Interrupt**: Ctrl+C saves partial results and generates a report

### Example

```bash
# Single target
python main.py -t ftp.example.com

# From file with 50 workers
python main.py -l targets.txt -w 50 -o found.txt --timeout 5
```

### Notes
- Prefixes like `http://` and `https://` are stripped automatically from targets
- Only the first few directory entries are sampled to keep the UI and reports readable

### Ethics & Legal
This tool is intended for defensive research, auditing, and education. Only scan targets you own or have explicit permission to test. You are solely responsible for your use of this tool.

### License
MIT


