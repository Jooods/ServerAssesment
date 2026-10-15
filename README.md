# Cloud Migration Assessment - Local Edition
Runnable Python source application, not a compiled EXE or production-certified platform.

## Windows
1. Install Python 3.10+ with Tcl/Tk (Tkinter).
2. Extract the ZIP into a writable local folder.
3. Double-click Start_Windows.bat. It creates .venv and installs psutil.
   Internet is needed for dependency installation. Scanning does not upload data.
4. Confirm authorization, choose duration/interval/headroom, click Start assessment.
5. Select a local output folder. Stop and save finishes early.
6. Open HTML report after completion. Keep the window open until finished.

Run the app ON the machine you want to assess. It does not remotely scan servers.
Start in the relevant normal user session to see mapped drives. A separate elevated
run may expose more system data, but only use privileges authorized by your IT team.
Permission failures are reported; permissions are not bypassed.

## Manual Windows launch
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe cloud_assessor.py

## Linux/headless
Requires Python 3.10+, venv and psutil. GUI also requires Tkinter and a desktop.
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python cloud_assessor.py --cli --authorized --seconds 3600 --interval 5

Windows CLI:
.venv\Scripts\python.exe cloud_assessor.py --cli --authorized --seconds 3600 --interval 5
Inventory only: --seconds 0 or GUI Minutes 0.
CLI --output PATH must point to an empty folder. Ctrl+C saves collected data.
Monitoring runs only while the process is open and the machine is awake.

## Included
CPU cores/logical processors, RAM/swap, OS, disks, interfaces and processes.
CPU/RAM average, peak, p95; per-interface receive/send Mbps and observed GiB.
Per-device IOPS/throughput and service-time estimates where available.
Listening ports and observed process-to-endpoint dependency lists.
Windows CIM hardware, SMB mappings/global mappings/hosted shares/SMB connections.
Linux mounts and SMB/NFS discovery where utilities are available.
Services, installed apps, scheduled tasks, DNS, routes and firewall-rule inventory.
Docker listing when its CLI is installed and authorized.
Configurable headroom and explicitly provisional sizing estimates.
Local HTML, JSON, CSV and raw JSONL exports. No cloud account or telemetry.

## Reports
report.html: readable report.
assessment.json: inventory, summaries, dependencies and limitations.
metrics.csv: CPU/memory samples.
dependencies.csv: observed process and network endpoints.
samples.jsonl: raw samples including network/disk metrics.
Reports contain hostnames, IPs, paths and application identifiers. Protect them.
No passwords, process command-line arguments or packet payloads are collected.
Linux /etc/resolv.conf and /proc/mounts are read for configuration discovery.

## Boundaries
This first version does not implement every enterprise feature in the proposed list.
No cloud SKU/pricing/API integration, multi-server aggregation, graphical dependency
map, comprehensive database/config discovery, automatic migration or complete
compatibility/readiness validation. Review OS support, licensing, backups, restore
checks and cloud networking manually.
Internet-only bytes and per-process traffic volumes are NOT measured.
Public/private IP classification does not prove routing or internet billing.
Do not sum interfaces blindly: VPN/virtual interfaces can duplicate traffic.
Sockets can miss short-lived connections and do not prove connection direction.
Disk layers/mountpoints can duplicate capacity/IO. Review before aggregating.
Disk service times are not application end-to-end latency.
SMB mappings are session-sensitive. Installed-app inventory is not exhaustive.
Missing permissions/utilities mean unavailable, not no dependencies.
Physical cores/logical processors are NOT equivalent to target cloud vCPUs.
CPU heuristic: logical processors * p95 CPU fraction * (1 + headroom/100),
rounded up, minimum 2. RAM: p95(total minus available) * headroom factor,
rounded up, minimum 2 GiB. Storage: used capacity plus headroom per mountpoint,
requiring device deduplication and growth review. These are NOT approved sizing.
Observe representative peaks, backups and batch jobs; validate/benchmark the target.
Inventory-only mode provides no utilization-based recommendation.
Stop takes effect after inventory collection; individual commands have timeouts.
Long sessions keep samples in memory as well as JSONL; use practical session lengths.

## Validation
Passed syntax compilation and actual Linux local inventory, monitoring and export
smoke checks; p95, empty-sample, address classification and nonnegative-rate checks.
Windows launcher/PowerShell collectors and interactive GUI were NOT executed on
Windows in the build environment. Test on a non-production machine first.

## Troubleshooting
Python not found: install Python or use its full executable path.
Dependency install failure: check approved internet/proxy settings with IT.
Tkinter missing: install Tcl/Tk or use CLI mode.
Access denied: inspect Warnings and obtain authorized access.
Mapped drive missing: run in the user session owning that mapping.
No sizing estimate: run monitoring rather than inventory-only.

## References
https://psutil.readthedocs.io/
https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbmapping


## Version 2: ten-pillar HTML
The HTML report now has ten numbered sections, navigation, tables, warnings and a manual-review checklist. Collectors and sizing formulas are unchanged.

New scans automatically use the new layout. To convert an existing assessment.json without rescanning, run Convert_Existing_Report_Windows.bat after setup and enter its full path without surrounding quotes. Output: report_10_pillars.html beside the JSON.

Manual conversion: python report_renderer.py "path/to/assessment.json"
No actual assessment data is bundled. Windows launcher and GUI remain untested in this build environment.
