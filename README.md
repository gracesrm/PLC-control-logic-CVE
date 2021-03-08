# PLC-control-logic-CVE

### Vulnerability Databases
This analysis is based on some interesting information, i.e. the reported Common Vulnerabilities and Exposures (CVE)s, their corresponding Common Weakness Enumeration (CWE)s, the impacted vendors and industrial sectors, the complexity of the CVEs, and their public exploits. We obtain the information from several sources: the [ICS-CERT](https://www.us-cert.gov/ics), the National Vulnerability Database ([NVD](https://nvd.nist.gov/vuln/data-feeds)), and the [Exploit Database](https://www.exploit-db.com) created by Offensive Security. 

The ICS-CERT reports timely security issues and vulnerabilities specifically in the industrial control systems. The NVD dataset contains general reports from all types of vulnerabilities, without details of affected industrial sectors and mitigation methods, as does by ICS-CERT. Nevertheless, the NVD dataset is less likely to miss data because of its popularity and has longer history (since 2002), while ICS-CERT provides data since 2010. The Exploit Database is a CVE compliant archive of public exploits, developed by penetration testers and vulnerability researchers. 

### Analysis Framework
We developed an analysis framework to first crawl and download data from the above sources, then extract interesting information on control logic related vulnerabilities, combine the results from all the datasets, and finally generate statistical reports from these information.

The extraction combines filtering notable PLC vendors, matching general keywords, such as *PLC*, *control logic*, and combining specific keywords such as *HMI* and *remote code execution*, meaning such vulnerability in the HMI can lead to control logic execution in the PLC. The vulnerability may exist in the following places: (1) PLC; (2) upper level components that affect running code on the PLCs (e.g. HMI, SCADA, engineering station); (3) the communication between a PLC and such components or among PLCs.

We randomly choose 100 CVEs from our collected datasets. We manually label them as control logic related or not, by going through the description of the vulnerability and checking online documentation of the affected products. We consider these labels as the ground truth. Then we run our automatic extraction framework and record control logic related CVEs. By comparing this record and the ground truth, we obtain the accuracy of our automatic extraction,
with false positive rate of 1\% and false negative rate of 4\%.

### Analysis Results
We have seen a fast growth of vulnerabilities in recent years.
![Yearly reported control logic related CVEs](https://github.com/gracesrm/PLC-control-logic-CVE/blob/master/fig/Common_CVE.pdf)

![The type of CWEs and their corresponding number reported per year](https://github.com/gracesrm/PLC-control-logic-CVE/blob/master/fig/Common_CWE.pdf)

Figure below shows the CVSS scores from both version 2 and version 3.
![The complexity of control logic related CVEs, depicted with the mean and the standard deviation of CVSS scores.](https://github.com/gracesrm/PLC-control-logic-CVE/blob/master/fig/Common_CVSS.pdf) Some points are missing as they are not reported in the databases.

For these reported CVEs, we also analyzed the top ten most affected vendors, as the following figure shows. 
![Notable PLC vendors and number of related control logic vulnerabilities reported per year](https://github.com/gracesrm/PLC-control-logic-CVE/blob/master/fig/Common_Vendor.pdf)

### Limitation
This framework may detect control logic vulnerabilities false positively. For example, 
a buffer overflow in a HMI binary that allows for remote code execution of a control program. 
