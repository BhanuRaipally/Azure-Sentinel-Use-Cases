# Azure Sentinel Use Cases 🛡️

MITRE ATT&CK based detection and response
use cases using Microsoft Azure Sentinel.

## What is Azure Sentinel?
Microsoft Azure Sentinel is a cloud-native 
SIEM and SOAR solution that provides:
- Real-time threat detection
- Automated incident response
- AI-powered investigation
- Centralized log management

## 🔍 Use Case 1 — Brute Force Detection

**Tactic:** Credential Access
**Technique:** T1110 - Brute Force

**Detection Query (KQL):**
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() 
  by Account, IpAddress
| where FailedAttempts > 10
| order by FailedAttempts desc

**Response Steps:**
1. Identify source IP
2. Check if account was compromised
3. Block IP in firewall
4. Reset user password
5. Enable MFA

## 🔍 Use Case 2 — Suspicious PowerShell

**Tactic:** Execution
**Technique:** T1059.001 - PowerShell

**Detection Query (KQL):**
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "powershell"
| where CommandLine contains "-enc"
   or CommandLine contains "-nop"
   or CommandLine contains "bypass"

**Response Steps:**
1. Investigate PowerShell command
2. Check parent process
3. Isolate machine if malicious
4. Scan for malware

## 🔍 Use Case 3 — Lateral Movement

**Tactic:** Lateral Movement
**Technique:** T1021 - Remote Services

**Detection Query (KQL):**
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| summarize count() by Account, IpAddress
| where count_ > 5

**Response Steps:**
1. Map affected systems
2. Isolate compromised accounts
3. Review network traffic
4. Block lateral movement paths

## 📚 References
- [Azure Sentinel Docs](https://docs.microsoft.com/azure/sentinel)
- [MITRE ATT&CK](https://attack.mitre.org)
- [KQL Reference](https://docs.microsoft.com/azure/data-explorer/kql-quick-reference)
