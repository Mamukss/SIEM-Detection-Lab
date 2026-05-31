# Custom SIEM Detection Rules

This repository documents the custom detection rule component of a defensive cybersecurity lab. The focus is on how suspicious activity can be converted from raw logs into meaningful SIEM alerts that can be reviewed, validated, and used for incident analysis.

> This project was created for educational and defensive security purposes in an isolated lab environment.

## Overview

The project focuses on detection engineering in a controlled environment. Custom SIEM and IDS rules were created to detect common suspicious behaviors such as:

- Repeated short network sessions
- Failed authentication attempts
- Possible brute-force behavior
- Abnormal traffic volume
- Flood-like packet activity

The goal of this section is not only to show that rules were written, but also to show how each rule was validated using multiple evidence sources.

## Lab Concept

The lab uses a separated virtual network where attack simulations are performed against a monitored target. The monitored target forwards security logs to a SIEM platform, while network traffic is also reviewed using an IDS and packet capture tool.

| Component | Role |
|---|---|
| Attacker Machine | Generates controlled security test traffic |
| Monitored Target | Receives connection attempts and authentication attempts |
| SIEM Platform | Collects logs, applies detection rules, and generates alerts |
| IDS Sensor | Detects suspicious network-level patterns |
| Packet Analyzer | Confirms traffic behavior at packet level |

## Detection Scope

| Detection Category | Purpose | Evidence Source |
|---|---|---|
| Reconnaissance Detection | Identify repeated probing or short session behavior | SIEM alerts, session logs, packet capture |
| Authentication Attack Detection | Detect repeated failed login activity | Authentication logs and SIEM correlation |
| Traffic Anomaly Detection | Detect high-volume or flood-like traffic | IDS alerts and packet capture |
| Alert Validation | Confirm that alerts match real observed behavior | SIEM, IDS, logs, and packet analysis |

## Custom SIEM Rules

The SIEM rules were designed to detect suspicious activity from monitored endpoint logs. These rules focus on short-lived sessions, failed authentication attempts, and repeated failed login patterns from the same source.

Example custom rule logic:

```xml
<group name="honeypot,authentication,">
  <rule id="300200" level="7">
    <decoded_as>json</decoded_as>
    <field name="eventid">session.closed</field>
    <description>Short session detected - possible reconnaissance or flood activity</description>
  </rule>

  <rule id="300400" level="5">
    <decoded_as>json</decoded_as>
    <field name="eventid">login.failed</field>
    <description>Failed authentication attempt detected</description>
  </rule>

  <rule id="300410" level="14" frequency="5" timeframe="60">
    <if_matched_sid>300400</if_matched_sid>
    <same_source_ip />
    <description>Possible brute-force behavior detected from the same source</description>
  </rule>
</group>
```

## IDS Local Rules

IDS rules were added to detect abnormal traffic volume within a short period of time. These rules help identify traffic patterns that may indicate flood-like behavior.

Example IDS rule logic:

```txt
alert tcp any any -> $HOME_NET any (
    msg:"Possible SYN flood activity detected";
    flags:S;
    threshold:type both, track by_src, count 100, seconds 1;
    sid:600010;
    rev:1;
)

alert tcp any any -> $HOME_NET any (
    msg:"Possible ACK flood activity detected";
    flags:A;
    threshold:type both, track by_src, count 100, seconds 1;
    sid:600011;
    rev:1;
)

alert udp any any -> $HOME_NET any (
    msg:"Possible UDP flood activity detected";
    threshold:type both, track by_src, count 200, seconds 1;
    sid:600012;
    rev:1;
)

alert icmp any any -> $HOME_NET any (
    msg:"Possible ICMP flood activity detected";
    itype:8;
    threshold:type both, track by_src, count 50, seconds 1;
    sid:600013;
    rev:1;
)
```

## Verification

The detection rules were verified by comparing alerts with raw logs and packet-level evidence. This helps confirm that the alerts were triggered by actual suspicious activity rather than false assumptions.

### Validation Workflow

1. Configure log forwarding from the monitored target to the SIEM.
2. Add custom SIEM rules for suspicious sessions and failed authentication.
3. Add IDS rules for abnormal packet volume.
4. Run controlled simulations in an isolated lab network.
5. Review raw endpoint logs.
6. Review SIEM alerts.
7. Review IDS alerts.
8. Compare the results with packet capture evidence.
9. Mark the detection as verified only when the alert matches the observed behavior.

## Detection Result Summary

| Detection Area | Expected Behavior | Verification Evidence | Status |
|---|---|---|---|
| Reconnaissance Activity | Short or repeated sessions are detected | Session logs, SIEM alert, packet capture | Verified |
| Failed Authentication | Failed login attempts are detected | Authentication logs and SIEM alert | Verified |
| Brute-force Pattern | Multiple failed logins from the same source are correlated | SIEM correlation alert | Verified |
| Traffic Flooding | High packet volume is detected | IDS alert and packet capture | Verified |
| Log Forwarding | Security events are received by the SIEM | Active agent/log source evidence | Verified |

## Evidence to Include

To make the project more credible on GitHub, include sanitized evidence files such as:

Ids anomaly in wireshark and siem alert

## Skills Demonstrated

- Detection engineering
- SIEM rule creation
- Log analysis
- Alert correlation
- IDS rule tuning
- Packet capture validation
- Authentication attack detection
- Reconnaissance detection
- Traffic anomaly detection
- Security monitoring in a virtual lab

## Disclaimer

All testing was performed in an isolated lab environment for educational and defensive cybersecurity purposes only. No public systems, third-party services, or unauthorized networks were targeted.
