# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Emranhossain27/Threat-hunting-folder/blob/main/Script/Threat-Hunt-Event%20-(TOR%20Usage).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management thinks some employees might be using the TOR browser to get around security controls. This suspicion comes from network logs showing strange encrypted traffic and connections to TOR entry nodes. On top of that, there were anonymous reports about employees talking about visiting restricted sites during work hours. The main goal is to check for TOR activity, review any related security incidents, and take action to reduce risks. If TOR use is confirmed, management should be notified.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file containing the string “tor” and found that the user “labuser” downloaded a Tor installer at 2025-09-01T15:22:11.0849944Z. This activity resulted in multiple Tor-related files being copied to the Desktop and the creation of a file named “tor-shopping-list.txt.” These events began at:

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "windows-hunt-10"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-09-01T15:04:33.521034Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1640" height="692" alt="image" src="https://github.com/user-attachments/assets/55b624aa-8fdb-44f2-a976-a74fc7635d7a" />


---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.6.exe.” Based on the logs returned, At 11:09:40 AM on September 1, 2025, on the Windows machine named windows-hunt-10, the user labuser launched a file named “tor-browser-windows-x86_64-portable-14.5.6.exe”—a standalone, portable version of the Tor Browser. The executable was sitting in the Downloads folder:
C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe. The process carried the SHA-256 hash 05866e47786df83847a08358067ea43cf919a4fe7c14b85fc9715ccb459d5e7e.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "windows-hunt-10"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1672" height="290" alt="image" src="https://github.com/user-attachments/assets/777434bf-1a6b-4a42-bbab-72a831039c9f" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the tor browser. There was evidence that they did open it at 2025-09-01T15:10:38.3503057Z. There were several other other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards 
Query used to locate events:

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "windows-hunt-10"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1642" height="607" alt="image" src="https://github.com/user-attachments/assets/5045cd77-3ae4-49c8-82c4-acf3ab0a888b" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the Tor browser was used to establish a connection using known Tor ports. On September 1, 2025, at 11:10:56 AM, on the Windows machine windows-hunt-10, the user labuser successfully established a network connection. The process responsible was tor.exe, located deep within the Tor Browser’s directory on the desktop (c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe). This connection was made to the remote IP 192.42.113.102 on port 9001—a port commonly associated in Tor network terminology as the ORPort, which is used by Tor relays for onion routing. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "windows-hunt-10"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001","9030","9050","9150","9051","9150")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1703" height="493" alt="image" src="https://github.com/user-attachments/assets/185f4acd-c122-417d-8b36-7f12b8f4aa97" />


---

## Chronological Event Timeline 

## Event Timeline

| Time (ISO/Readable)       | Event Description                                                                 |
|----------------------------|---------------------------------------------------------------------------------|
| 2025-09-01 11:09:40        | User ran the Tor Browser installer from Downloads (`tor-browser-windows-x86_64-portable-14.5.6.exe`). |
| 2025-09-01 11:10:56        | `tor.exe` initiated a successful ORPort connection (port 9001) to IP `192.42.113.102`. |
| 2025-09-01 15:10:38.3503057 | Multiple Tor-related processes (`firefox.exe`, `tor.exe`, etc.) were executed by **labuser**. |
| 2025-09-01 15:22:11.0849944Z | The Tor installer was downloaded, and Tor-related files appeared on the Desktop, including `tor-shopping-list.txt`. |


## Summary

Tor installer downloaded: At 2025‑09‑01T15:22:11 Z, the user labuser downloaded the Tor Browser installer on the device windows-hunt-10.
Tor Browser executed: Shortly before, at 11:09:40 AM (local time) on September 1, 2025, labuser launched the Tor Browser executable from the Downloads folder.
Tor-related processes initiated: After installation, several Tor-related processes—such as tor.exe, firefox.exe, and tor-browser.exe were executed, confirming active Tor Browser usage. Outbound Tor connection observed: At 11:10:56 AM, tor.exe successfully connected to a remote IP over port 9001, a known Tor relay (ORPort), indicating network activity via the Tor network.

---

## Response Taken

TOR usage was confirmed on endpoint  windows-hunt-10 by the user labuser. The device was isolated and the user's direct manager was notified.

---

## MITRE ATT&CK Mapping

The following techniques from the MITRE ATT&CK framework align with the observed activity:
T1105 – Ingress Tool Transfer: The user downloaded the Tor Browser installer (tor-browser-windows-x86_64-portable-14.5.6.exe).
T1059 – Command and Scripting Interpreter: The Tor installer and processes (tor.exe, firefox.exe) were executed locally.
T1071.001 – Application Layer Protocol: Web Traffic: The Tor client established encrypted outbound connections over port 9001 to a known Tor entry node.
T1204 – User Execution: The employee intentionally executed the Tor installer and browser.

---

## Recommendations

To reduce risk of unauthorized Tor usage in the environment:

1. Network Controls: Block known Tor ports (9001, 9030, 9050, 9051, 9150) at perimeter firewalls and proxy servers.
2. File & Process Monitoring: Deploy endpoint monitoring rules to alert on the creation or execution of tor.exe, firefox.exe within unusual directories (e.g., Desktop, Downloads).
3. Application Whitelisting: Implement AppLocker or similar solutions to prevent execution of unauthorized software.
4. Policy Enforcement: Update and communicate the Acceptable Use Policy (AUP) to employees, explicitly prohibiting Tor usage.
5. User Awareness Training: Conduct training on the risks of anonymity networks and consequences of policy violations.
6. Threat Intelligence Integration: Regularly ingest updated IoCs (e.g., Tor node IPs, hashes) into SIEM for detection
---
