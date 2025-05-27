# Threat-hunting-scenario--bruteforce-attack

# Table of Contents

- [ Scenario](#scenario)
- [ Platforms and Tools](#platforms-and-tools)
- [ Part 1: Create Alert Rule](#part-1-create-alert-rule)
- [ Part 2: Trigger Alert to Create Incident](#part-2-trigger-alert-to-create-incident)
- [ Part 3: Working the Incident](#part-3-working-the-incident)
  - [ 3.1 Preparation](#31-preparation)
  - [ 3.2 Detection and Analysis](#32-detection-and-analysis)
  - [ 3.3 Containment, Eradication, and Recovery](#33-containment-eradication-and-recovery)
  - [ 3.4 Post-Incident Activities](#34-post-incident-activities)
  - [ 3.5 Incident Closure](#35-incident-closure)
- [ Summary](#summary)
  

# Scenario 

As a Security Analyst at a pharmaceutical company, I discovered that several critical infrastructure devices hosted on Microsoft Azure were experiencing multiple failed logon attempts.
My objective was to investigate, detect, and mitigate the incident in alignment with the **NIST SP 800-61** guidelines for incident handling



<a name="platforms-and-tools"></a>
#  Platforms and Tools

•	Microsoft Sentinel<br>
•	Microsoft Defender for Endpoint<br>
•	Kusto Query Language (KQL)<br>
•	Windows 10 Virtual Machines (Microsoft Azure)<br>

# Part 1: Create Alert Rule

<img src="https://github.com/user-attachments/assets/b07c643e-dba3-4a50-af2f-fcf313e95e82">

Steps Taken:
I gave the name for the Alert , gave it a description, assigned a severity level to medium and included relevant MITRE ATT&CK categories based on the query language. 

<img src="https://github.com/user-attachments/assets/2ad0e102-3b1a-4cc9-922e-490f62f087fe" >

I set the alert rule, entity like device name and remote ip  mapped for further investigation 

**Rule Query:**

```
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where Timegenerated >= ago(5h)
| summarize numberoffailure  = count() by RemoteIP, DeviceName, ActionType
| where numberoffailure >= 50
|order by numberoffailure
```

<img src="https://github.com/user-attachments/assets/973e5bb5-a25d-47af-b1da-3b57dd0e7892" >

In the incident settings, I grouped the alert into a single incident to reduce alert noise.

The rule was validated and saved in Azure Analytics 

# Part 2: Trigger Alert to Create Incident 

<img src="https://i.imgur.com/uocxpPo.png">

The alert rule worked successfully, and it got triggered in the ‘Incidents’ tab within Microsoft Sentinel. This resulted from 7 different events which triggered the alert which triggered with the incident.  

# Part 3: Working the Incident 

I will now be proceeding with this incident in alignment with the NIST SP 800-61 Incident Response Lifecycle framework, which includes the following phases: Preparation, Detection and Analysis, Containment, Eradication and Recovery, and Post-Incident Activity.

## 3.1 Preparation

•	Document roles, responsibilities, and procedures.<br>
•	Ensure tools, systems, and training are in place.<br>

(This step is assumed to be already completed and is therefore skipped for the purpose of this lab.)<br>

## 3.2 Detection and Analysis

•	Identify and validate the incident.<br>
•	Gather relevant evidence and assess impact.<br>

<img src="https://i.imgur.com/WV9oGg8.png">

I will assign this incident to myself by clicking ‘Assign to me’ and change its status to ‘Active’. 

<img src="https://i.imgur.com/6Clwwac.png">

After going into the investigation view of this incident. We can notice that 6 machines were potentially impacted by brute force attempts from 7 different public IP addresses.

<img src="https://i.imgur.com/7fE1tHD.png">

Next, I will check to make sure none of the IP addresses attempting to brute force the machine logged in. 

<img src="https://i.imgur.com/XaqaG1F.png">

**KQL Query Used:**

```
DeviceLogonEvents
| where RemoteIP in ("92.42.15.193", "124.43.77.66", "188.246.224.72", "152.52.85.138", "185.243.96.107", "193.37.69.105")
| where ActionType != "LogonFailed"
```

None of the brute force attempts were successful.

## 3.3 Containment, Eradication, and Recovery

To isolate these machines, I will use Defender for Endpoint.

<img src="https://i.imgur.com/r0lczYf.png">

I navigated to the Assets tab, selected Devices, located the affected device(s), clicked the three-dot menu, and chose 'Isolate Device'. After isolation, I would initiate an antivirus scan on all affected devices within Microsoft Defender for Endpoint (MDE).

**Removing the threat:**

➡️ NSG was locked down to prevent RDP attempts from the public internet.<br>
➡️ Corporate policy was proposed to require this for all VMs going forward. (This can be done with Azure Policy)<br>

Brute force was not successful, so no threats related to this incident.

## 3.4 Post-Incident Activities

•	Document findings and lessons learned.<br>
•	Update policies and tools to prevent recurrence.<br>

<img src="https://i.imgur.com/5BuLkge.png">

I recorded the incident notes in the activity log.

## 3.5 Incident Closure

<img src="https://i.imgur.com/jSFgQXG.png">

I marked this case as a True Positive and closed it out.

# Summary

In this lab, I demonstrated key skills relevant to a SOC Analyst role, including threat detection, incident investigation, and response. I created and configured an alert rule in Microsoft Sentinel to detect potential brute-force attacks, analysed failed login attempts to validate the incident, and isolated affected systems using Microsoft Defender for Endpoint. I also applied mitigation measures by updating NSG settings to block public RDP access and recommended policy changes to prevent future threats. This hands-on experience showcases my ability to proactively monitor, respond to incidents, and implement security measures in a live environment, all of which are essential for a SOC Analyst position.

