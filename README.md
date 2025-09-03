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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
