# Detection rules

| Rule ID | Detection | Severity | MITRE ATT&CK | Logic |
|---|---|---:|---|---|
| SOC-AUTH-001 | Possible SSH brute force | High | T1110 | At least 5 failed SSH logins for the same user/source within 5 minutes |
| SOC-AUTH-002 | Failed login burst | High | T1110 | Same threshold for non-SSH authentication failures |
| SOC-ACCOUNT-001 | New account created | Medium | T1136 | Linux `useradd/adduser` or Windows Event ID 4720 |
| SOC-PRIV-001 | Sudo command | Low | T1548.003 | Linux sudo command with user and command evidence |
| SOC-PROC-001 | Suspicious process | High/Critical | T1059, T1218 | LOLBins, encoded PowerShell, credential-dumping tooling |
| SOC-PERSIST-001 | Windows service created | High | T1543.003 | Windows Event ID 7045 |

Thresholds are configurable through environment variables. Rules are intentionally readable and deterministic so an interviewer can review the detection reasoning directly in code.
