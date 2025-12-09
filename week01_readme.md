# Week 01: Foundations of Computer Security

## Overview
This week established the fundamental framework for security analysis through the CIA Triad (Confidentiality, Integrity, Availability). By examining six major security breaches, I developed the ability to classify incidents and understand cascading security impacts.

---

## Learning Objectives Achieved
Discuss computer security concepts in practical contexts
Apply the CIA Triad to analyse real-world security scenarios
Differentiate between passive and active security attacks
Conduct career-focused skills gap analysis

---

## Activities Completed

### 1. CIA Triad Case Study Analysis

#### Case A: 2017 Equifax Data Breach
**Primary Impact**: **Confidentiality**

**Justification**: The breach exposed personal and financial data of 147.9 million people, including SSNs, birth dates, addresses, and credit card numbers. This is a textbook confidentiality violation—unauthorised disclosure of sensitive information.

**Secondary Impacts**:
- **Integrity**: Some consumer data may have been modified during the breach
- **Availability**: Services were temporarily disrupted during incident response

**Key Takeaway**: The breach occurred through an unpatched Apache Struts vulnerability (CVE-2017-5638), demonstrating how patch management failures cascade into massive confidentiality breaches.

---

#### Case B: The Stuxnet Worm
**Primary Impact**: **Integrity**

**Justification**: Stuxnet's goal wasn't data theft but sabotage. It modified the behaviour of PLCs controlling centrifuges, causing them to malfunction while reporting normal operation. This manipulation of industrial control system integrity caused physical destruction.

**Secondary Impacts**:
- **Availability**: Centrifuges were rendered inoperable
- **Confidentiality**: The worm's existence revealed capabilities and intelligence

**Key Takeaway**: Stuxnet redefined cybersecurity by demonstrating that malware can cause kinetic, physical-world damage. It introduced the concept of cyber-physical attacks and highlighted vulnerabilities in critical infrastructure.

---

#### Case C: 2016 Dyn DNS DDoS Attack
**Primary Impact**: **Availability**

**Justification**: The Mirai botnet overwhelmed Dyn's DNS infrastructure, making major websites (Twitter, Netflix, Reddit, GitHub) unreachable for hours. No data was stolen or modified—only service availability was impacted.

**Secondary Impacts**:
- **Integrity**: Minimal—DNS records remained accurate
- **Confidentiality**: None—no data exposure occurred

**Key Takeaway**: This attack exploited IoT devices (cameras, DVRs) with default credentials, demonstrating the security risks of the expanding IoT ecosystem. It showed how availability attacks can have widespread economic impact despite not directly compromising data.

---

#### Case D: 2021 Colonial Pipeline Ransomware Attack
**Primary Impact**: **Availability**

**Justification**: The DarkSide ransomware encrypted systems, forcing a complete pipeline shutdown. The attack prevented access to critical fuel distribution infrastructure for several days, causing fuel shortages across the East Coast.

**Secondary Impacts**:
- **Confidentiality**: ~100GB of data was exfiltrated before encryption
- **Integrity**: Encrypted files represent integrity loss (data rendered unusable)

**Key Takeaway**: Ransomware is primarily an availability attack, but modern variants (double extortion) add confidentiality breaches. The $4.4M ransom payment and economic disruption showed the real-world impact of attacks on critical infrastructure.

---

#### Case E: 2023 MOVEit Supply Chain Attack
**Primary Impact**: **Confidentiality**

**Justification**: The Cl0p ransomware gang exploited a zero-day SQL injection vulnerability in MOVEit Transfer software to exfiltrate sensitive data from thousands of organisations (BBC, British Airways, government agencies). The core impact was unauthorised data disclosure.

**Secondary Impacts**:
- **Integrity**: Attackers potentially modified web shells on compromised servers
- **Availability**: Some organisations took systems offline during remediation

**Key Takeaway**: Supply chain attacks amplify impact—compromising one widely-used software affects thousands of downstream organisations. This demonstrates the importance of third-party risk management and zero-trust architectures.

---

#### Case F: 2020 SolarWinds Supply Chain Attack
**Primary Impact**: **Confidentiality**

**Justification**: The Sunburst backdoor provided attackers (attributed to Russian APT29) with long-term, stealthy access to networks of government agencies and Fortune 500 companies. The primary goal was espionage—stealing sensitive information, intellectual property, and strategic communications.

**Secondary Impacts**:
- **Integrity**: Malicious code was injected into legitimate software updates
- **Availability**: Remediation required organisations to shut down systems

**Key Takeaway**: This attack demonstrated sophisticated supply chain compromise at the software build level. It revealed the challenge of detecting advanced persistent threats (APTs) that blend into legitimate network traffic and highlighted the need for supply chain security verification.

---

### 2. Career Assessment

#### Job Roles Researched

**Role 1: Security Analyst - Accenture**
- **Company Fit**: Strong fit. Large consultancy with diverse clients, excellent learning opportunities, structured career progression
- **Key Requirements**:
- Understanding of SIEM tools (Splunk, QRadar)
- Incident response procedures
- Vulnerability assessment
- Security frameworks (NIST, ISO 27001)

**Role 2: Application Security Engineer - Shopify**
- **Company Fit**: Good fit. Focus on e-commerce security, modern tech stack, strong security culture
- **Key Requirements**:
- Secure code review
- OWASP Top 10 knowledge
- Penetration testing
- Programming (Python, Ruby)

**Role 3: Threat Intelligence Analyst - CrowdStrike**
- **Company Fit**: Excellent fit. Industry-leading threat intelligence, cutting-edge tools, APT research focus
- **Key Requirements**:
- Malware analysis
- Threat modelling
- IOC generation and sharing
- Intelligence reporting

---

#### Skills Gap Analysis

| Skill/Qualification | Current Status | Evidence | Development Plan |
|-------------------|---------------|----------|-----------------|
| **SIEM Tools** | Developing | Basic Splunk exposure in previous module | Complete Splunk Fundamentals certification |
| **Python Security Scripting** | Have it | This module's cryptography and scanning scripts | Continue building automation tools |
| **Vulnerability Assessment** | Developing | Week 5 Wapiti scanning | Practise on HackTheBox, TryHackMe platforms |
| **Malware Analysis** | Developing | Week 6 static analysis | Expand to dynamic analysis with Cuckoo Sandbox |
| **Penetration Testing** | Developing | Week 7 reconnaissance and scanning | Pursue OSCP or eJPT certification |
| **Incident Response** | No | Limited exposure | Complete SANS SEC504 or BTL1 course |
| **Threat Intelligence** | Developing | Reading threat reports, IOC analysis | Contribute to open-source threat intel projects |
| **Cloud Security** | No | No hands-on experience | Gain AWS/Azure security certifications |
| **Reverse Engineering** | No | Only static analysis | Learn x86 assembly, IDA Pro, Ghidra |

---

#### Action Plan: Top 3 Skills to Develop

1. **Hands-on Penetration Testing**
- **Timeline**: 3-6 months
- **Actions**:
- Complete TryHackMe learning paths (Offencive Pentesting)
- Practise on HackTheBox retired machines
- Work toward eJPT certification
- Document findings in portfolio

2. **Incident Response & Forensics**
- **Timeline**: 6-12 months
- **Actions**:
- Study NIST incident response framework
- Set up home lab for forensic analysis (FTK Imager, Autopsy)
- Participate in CTF competitions (forensics challenges)
- Volunteer for university security team

3. **Cloud Security (AWS)**
- **Timeline**: 4-6 months
- **Actions**:
- Complete AWS Security Fundamentals course
- Practise securing S3 buckets, IAM policies, VPCs
- Pursue AWS Certified Security - Speciality
- Build secure cloud architectures in personal projects

---

## Reflection

### What I Learnt
This week fundamentally changed how I analyse security incidents. Before, I might have said the Colonial Pipeline attack was "a hack that shut down a pipeline." Now, I understand it as:
- **Primary**: Availability attack via ransomware encryption
- **Vector**: Likely initial access through VPN with compromised credentials
- **Business Impact**: $4.4M ransom, fuel shortages, government emergency declaration
- **Defencive Gaps**: Lack of network segmentation, insufficient backup procedures, inadequate credential management

The CIA Triad provides a structured framework for incident analysis that moves beyond "they got hacked" to precise categorisation of security failures.

### Challenges
Initially, I struggled with cases having overlapping impacts (e.g., Colonial Pipeline involved both availability and confidentiality). I learnt that identifying the *primary* impact requires asking: "What was the attacker's main goal, and what was the most severe consequence?"

### Career Insights
The skills gap analysis was eye-opening. While I'm developing strong foundations (cryptography, scripting, vulnerability assessment), the market demands broader skills including:
- **SIEM/SOC tools** (Splunk, QRadar, ELK)
- **Cloud security** (AWS/Azure security controls)
- **Incident response** (forensics, containment, remediation)

This portfolio approach addresses this gap by demonstrating practical skills employers can evaluate.

### Real-World Connection
The case studies showed that security breaches aren't just technical failures—they have:
- **Economic impact**: Colonial Pipeline fuel shortages, Equifax stock drop
- **Political consequences**: SolarWinds led to congressional hearings
- **Human cost**: Equifax victims faced identity theft for years

This reinforced that security professionals carry significant responsibility. Our work directly protects people, organisations, and critical infrastructure.

---

## Resources Used
- NCSC Annual Review 2021: https://www.ncsc.gov.uk/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- LinkedIn Job Search: cybersecurity analyst, application security engineer
- CrowdStrike threat intelligence blog
- Krebs on Security blog (breach analysis)