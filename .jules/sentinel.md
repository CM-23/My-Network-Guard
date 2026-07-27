## 2026-07-27 - Found Command Injection Vulnerabilities
**Vulnerability:** Command injection in `sniffer.py` and `wifi_manager.py` due to `subprocess.check_output(..., shell=True)` without proper sanitization (though most calls use static strings, any future dynamic usage would be highly dangerous, and some might already take user input indirectly).
**Learning:** The use of `shell=True` in `subprocess` calls is inherently risky and often unnecessary. It allows shell metacharacters to be interpreted, leading to command injection if input is not meticulously sanitized.
**Prevention:** Avoid `shell=True` whenever possible. Pass commands and arguments as a list of strings to `subprocess` functions. If `shell=True` is absolutely necessary, use `shlex.quote` to escape all variables.
