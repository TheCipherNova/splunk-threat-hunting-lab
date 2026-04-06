# Splunk Query Reference – Threat Hunting Lab

This document contains the Splunk queries used during the investigation, mapped directly to the corresponding screenshots.

---

## 01_failed_logons_4625.png 
 
### Failed Logon Detection

```spl
index=main "Event ID"=4625
````

Detects failed login attempts that may indicate brute-force activity.

## 02_target_user_extraction.png

### Extract Target User

```spl
index=main "Event ID"=4625
| rex "Account For Which Logon Failed:\s+Security ID:\s+.*\s+Account Name:\s+(?<target_user>\w+)"
| table _time "Event ID" target_user
```

Extracts the account being targeted during failed login attempts.

## 03_failed_logon_count.png

### Brute Force Detection (Count Attempts)

```spl
index=main "Event ID"=4625
| rex "Account For Which Logon Failed:\s+Security ID:\s+.*\s+Account Name:\s+(?<target_user>\w+)"
| stats count by target_user
```

Counts failed login attempts per user to identify brute-force patterns.

## 04_attack_timeline.png

### Timeline Correlation

```spl
index=main ("Event ID"=4624 OR "Event ID"=4625)
| table _time "Event ID"
| sort _time
```

Correlates failed and successful login events to reconstruct the attack sequence.

## 05_successful_logon_4624.png

### Successful Logon Detection

```spl
index=main "Event ID"=4624
```

Identifies successful authentication events after brute-force attempts.

## 06_privilege_escalation_4732.png

### Privilege Escalation Detection

```spl
index=main "Event ID"=4732
```

Detects when a user is added to a privileged group (e.g., Administrators).

---

## Summary

These queries were used to detect and analyze a multi-stage attack involving:

* Multiple failed login attempts (brute force)
* Credential compromise (successful login)
* Privilege escalation (admin group membership)

This reflects a real-world SOC investigation workflow using Splunk.
