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

<img src="https://github.com/user-attachments/assets/3dd4a3fa-11f7-4c93-b55e-4ec9c2815a8e">

The alert  worked successfully, and it got triggered in the ‘Incidents’ tab within Microsoft Sentinel. This resulted in  10 different incident .

# Part 3: Working Incident 

The alert created the incident .Work Incident in alignment with the NIST SP 800-61 Incident Response Lifecycle framework, which includes the following phases: Preparation, Detection and Analysis, Containment, Eradication and Recovery, and Post-Incident Activity.

## 3.1 Preparation

•	Document roles, responsibilities, and procedures.<br>
•	Ensure tools, systems, and training are in place.<br>


## 3.2 Detection and Analysis

•	Identify and validate the incident.<br>
  -Observe the incident and assign it to myself by selecting 'Assign to myself' and  set the status to active.<br>
  
  <img src="https://github.com/user-attachments/assets/796b2c9b-4224-4884-8777-4ec6985b6657">
  
•	Gather relevant evidence and assess impact.<br>
   -Observe the different entity mappings <br>

<img src="https://github.com/user-attachments/assets/bd64ac27-7eef-48f3-a860-e28c372180da"><br>

After going through the  investigation view of Remyahk-create alert rule  We can notice that 10 different virtual machines were potentially impacted by brute force attempts from 7 different public IP addresses.

<img src="https://github.com/user-attachments/assets/437b7491-3424-4833-8e4a-aa54e54de54c">

Next, I will check to make sure none of the IP addresses attempting to brute force the machine logged in. 

<img src="https://github.com/user-attachments/assets/f5f3222e-e177-4a14-874d-2bf3f3ba9d8b">

**KQL Query Used:**

```
DeviceLogonEvents
| where TimeGenerated > ago(5h)
| where RemoteIP in ("10.0.0.8", "122.165.219.142", "179.60.146.60", "122.165.219.142", "114.5.202.25", "114.5.202.25", "209.195.1.108", "122.165.219.142")
| where ActionType != "LogonFailed"
| project RemoteIP, DeviceName, ActionType
```

The  brute force attempt on one of the device was successfull from the Remote IP 10.0.0.8.
All the other devices brute force attack was unsuccessfull.

## 3.3 Containment, Eradication, and Recovery

Isolated the affected devices and ran antivirus scan.

<img src="https://github.com/user-attachments/assets/643cfef7-8610-4923-897e-c7a61f2145c0"><br>

To perform this ,I went to Microsoft Defender , navigated to the Assets tab, selected Devices, located the affected devices and chose'Isolate Device'. After isolation, I would ran  an antivirus scan on all affected devices within Microsoft Defender for Endpoint (MDE).

**Removing the threat:**

➡ NSG was locked down to prevent RDP attempts from the public internet.<br>
➡ Corporate policy was proposed to require this for all VMs going forward. (This can be done with Azure Policy)<br>

Removed the threat and restore the system to normal.

## 3.4 Post-Incident Activities

•	Document findings and lessons learned.<br>
•	Update policies and tools to prevent recurrence.<br>




## 3.5 Incident Closure

<img src="https://github.com/user-attachments/assets/a10f8795-e6f3-4f18-b7f5-4ba37bcd4b7a"><br>
I documented  the incident  activity in the activity log.<br>
I marked this case as a True Positive and closed it out.<br>

# Summary
Through this lab, I gained hands-on experience in detecting and responding to brute-force attacks using Microsoft Sentinel and KQL. I developed skills in crafting custom detection rules and aligning them with MITRE ATT&CK techniques to enhance threat intelligence. I also learned how to investigate incidents efficiently within Microsoft Defender for Endpoint, including isolating compromised devices and analyzing attack paths. Additionally, I applied the NIST SP 800-61 framework to structure my incident response process from detection to recovery. This lab improved my technical investigation capabilities and reinforced the importance of proactive network hardening.


