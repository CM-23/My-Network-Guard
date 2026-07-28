## 2024-05-24 - [Avoid `shell=True` in subprocess calls]
**Vulnerability:** Found multiple usages of `shell=True` when invoking `subprocess.check_output` in Python scripts (`sniffer.py` and `wifi_manager.py`).
**Learning:** Even if the command string appears static or hardcoded, using `shell=True` is an anti-pattern. If dynamic input were eventually added to these commands, it could lead to Command Injection (shell injection) vulnerabilities.
**Prevention:** Always invoke subprocess functions with a list of arguments (`shell=False`, which is the default).
