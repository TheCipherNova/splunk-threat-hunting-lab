# Incident Report – Brute Force Attack and Privilege Escalation

## 1. Incident Overview

This report documents a security incident involving a brute-force attack that led to account compromise and privilege escalation.

The investigation was conducted using Splunk by analyzing Windows Security Event Logs.

---

## 2. Incident Summary

- **Attack Type:** Brute Force → Credential Compromise → Privilege Escalation  
- **Target System:** Windows Host (DESKTOP-6J96G96)  
- **Affected User:** user1  
- **Total Failed Attempts:** 8  
- **Outcome:** Successful login followed by administrative privilege assignment  

---

## 3. Timeline of Events

| Time                     | Event ID | Description                              |
|--------------------------|----------|------------------------------------------|
| 12:38:35 – 12:38:58      | 4625     | Multiple failed login attempts detected  |
| 12:39:04                 | 4624     | Successful login observed                |
| 12:39:23                 | 4732     | User added to Administrators group       |

---

## 4. Detailed Analysis

### 4.1 Brute Force Activity (Event ID 4625)

Multiple failed login attempts were detected against the account **user1** within a short time window.

**Key Indicators:**
- Repeated authentication failures  
- Same target account  
- Short time interval between attempts  

**Conclusion:**  
This pattern is consistent with a brute-force attack.

---

### 4.2 Credential Compromise (Event ID 4624)

A successful login event was observed shortly after multiple failed attempts.

**Key Indicators:**
- Successful authentication following failures  
- Same timeframe as attack  

**Conclusion:**  
The attacker likely succeeded in guessing the correct password.

---

### 4.3 Privilege Escalation (Event ID 4732)

The compromised account was added to the Administrators group.

**Key Indicators:**
- Group membership modification  
- Addition to privileged group (Administrators)  

**Conclusion:**  
The attacker escalated privileges to gain administrative access.

---

## 5. Attack Chain

1. Attacker performs brute-force login attempts (4625)  
2. Credentials are successfully guessed (4624)  
3. Access is gained to the system  
4. Privileges are escalated (4732)  

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Description |
|----------|----|------------|
| Brute Force | T1110 | Password guessing attack |
| Valid Accounts | T1078 | Use of compromised credentials |
| Privilege Escalation | T1068 | Elevating access rights |

---

## 7. Impact Assessment

If left undetected, this attack could result in:

- Unauthorized system access  
- Administrative control over the host  
- Potential lateral movement or persistence  

---

## 8. Recommendations

### Detection Improvements
- Alert on multiple failed login attempts within a short timeframe  
- Correlate failed logins followed by successful login  

### Prevention Measures
- Implement account lockout policies  
- Enforce strong password policies  
- Enable multi-factor authentication (MFA)  

### Monitoring Enhancements
- Monitor group membership changes (Event ID 4732)  
- Track suspicious login behavior across systems  

---

## 9. Conclusion

This incident demonstrates a complete attack chain starting from brute-force attempts to privilege escalation.

By correlating authentication logs and security events in Splunk, it was possible to identify malicious behavior and reconstruct the attack timeline.

This reflects a real-world SOC investigation workflow and highlights the importance of log analysis in threat detection.
