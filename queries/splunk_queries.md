# Splunk Query Reference – Threat Hunting Lab

This document contains the Splunk queries used during the investigation, mapped directly to the corresponding screenshots.

---

## 1. Failed Logon Detection

```spl
index=main "Event ID"=4625
````

Detects failed login attempts that may indicate brute-force activity.

---

## 2. Extract Target User

```spl
index=main "Event ID"=4625
| rex "Account For Which Logon Failed:\s+Security ID:\s+.*\s+Account Name:\s+(?<target_user>\w+)"
| table _time "Event ID" target_user
```

Extracts the account being targeted during failed login attempts.

---

## 3. Brute Force Detection (Count Attempts)

```spl
index=main "Event ID"=4625
| rex "Account For Which Logon Failed:\s+Security ID:\s+.*\s+Account Name:\s+(?<target_user>\w+)"
| stats count by target_user
```

Counts failed login attempts per user to identify brute-force patterns.

---

## 4. Timeline Correlation

```spl
index=main ("Event ID"=4624 OR "Event ID"=4625)
| table _time "Event ID"
| sort _time
```

Correlates failed and successful login events to reconstruct the attack sequence.

---

## 5. Successful Logon Detection

```spl
index=main "Event ID"=4624
```

Identifies successful authentication events after brute-force attempts.

---

## 6. Privilege Escalation Detection

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
