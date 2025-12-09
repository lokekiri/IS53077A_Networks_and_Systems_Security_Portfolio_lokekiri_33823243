# Networks and Systems Security - E-Portfolio

[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-yellow.svg)](https://opensource.org/licences/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Learning Outcomes](#learning-outcomes)
- [Weekly Progress](#weekly-progress)
- [Key Skills Demonstrated](#key-skills-demonstrated)
- [Reflective Summary](#reflective-summary)
- [References](#references)

---

## Overview

This e-portfolio documents my practical engagement with Networks and Systems Security throughout the academic term. Each week builds upon foundational security principles, progressing from theoretical concepts to hands-on implementation of security tools, cryptographic systems, vulnerability assessment, and emerging AI security challenges.

**Module Focus Areas:**
- Security Fundamentals (CIA Triad, Attack Taxonomy)
- Applied Cryptography (RSA, Hybrid Encryption)
- Web Application Security (Vulnerability Scanning, OWASP)
- Malware Analysis (Static Analysis, PE Headers, YARA)
- Penetration Testing (Reconnaissance, Port Scanning, Ethical Hacking)
- Generative AI Security (LLM Vulnerabilities, Prompt Injection)

---

## Learning Outcomes

Through this portfolio, I demonstrate competency in:

1. **Security Analysis**: Applying the CIA Triad to real-world breach scenarios and identifying primary security impacts
2. **Cryptographic Implementation**: Building secure communication channels using RSA and AES encryption
3. **Vulnerability Assessment**: Conducting ethical web application security testing using industry-standard tools
4. **Malware Triage**: Performing static analysis on executables to extract IOCs and behavioural indicators
5. **Penetration Testing**: Executing reconnaissance and network scanning within legal and ethical boundaries
6. **AI Security**: Identifying and testing generative AI vulnerabilities including prompt injection and model extraction

---

## Weekly Progress

### [Week 01: Foundations of Computer Security](./week01/)
**Topics**: CIA Triad, Security Breach Analysis, Career Assessment

- Analysed 6 major security breaches (Equifax, Stuxnet, Colonial Pipeline, etc.)
- Identified primary CIA violations and secondary impacts
- Completed skills gap analysis for 3 cybersecurity job roles
- [Case Study Analysis](./week01/cia_analysis.md)
- [Career Research Document](./week01/career_assessment.md)

**Key Insight**: The 2016 Dyn DDoS attack demonstrated how availability breaches can cascade across internet infrastructure, affecting millions. This reinforced the importance of redundancy and DDoS mitigation strategies in critical systems.

---

### [Week 02: RSA Algorithm & Secure Communication](./week02/)
**Topics**: Asymmetric Cryptography, Socket Programming, Key Exchange

- Generated RSA key pairs (2048-bit) with proper serialisation
- Implemented hybrid encryption (RSA + AES-256-CFB)
- Created client-server secure messaging system
- [Key Generation Script](./week02/generate_keys.py)
- [Receiver (Server) Implementation](./week02/receiver.py)
- [Sender (Client) Implementation](./week02/sender.py)
- [Peer Feedback Document](./week02/peer_feedback.md)

**Key Insight**: Hybrid encryption leverages the efficiency of symmetric encryption (AES) for data and the security of asymmetric encryption (RSA) for key exchange. This approach is fundamental to protocols like TLS/SSL.

---

### [Week 03: Advanced Cryptographic Applications](./week03/)
**Topics**: Cryptographic Protocol Design, Secure Messaging

- Enhanced encryption implementation with error handling
- Tested message integrity across network transmission
- Documented encryption/decryption workflow
- [Enhanced Implementation](./week03/secure_messaging/)
- [Performance Analysis](./week03/crypto_performance.md)

**Key Insight**: The OAEP padding scheme (used in RSA) provides semantic security, preventing attackers from deriving meaningful information from ciphertext patterns.

---

### [Week 04: Cryptographic Optimisation](./week04/)
**Topics**: Security Best Practises, Protocol Hardening

- Implemented secure key storage practises
- Added authentication layer to messaging system
- Conducted security review of implementation
- [Hardened Implementation](./week04/hardened_system/)
- [Security Review](./week04/security_review.md)

**Key Insight**: Key management is often the weakest link in cryptographic systems. Proper key rotation, secure storage, and access control are as critical as the algorithms themselves.

---

### [Week 05: Web Application Security](./week05/)
**Topics**: Vulnerability Scanning, OWASP Top 10, Ethical Testing

- Deployed and configured Wapiti scanner
- Scanned OWASP Juice Shop and Google Gruyere instances
- Identified XSS, SQLi, and CSRF vulnerabilities
- Generated comprehensive security reports
- [Wapiti Scanning Scripts](./week05/wapiti_scan.py)
- [Vulnerability Assessment Report](./week05/vulnerability_report.md)
   [OWASP Top 10 Analysis](./week05/owasp_analysis.md)

**Key Insight**: Automated scanners like Wapiti excel at discovering common vulnerabilities but require manual verification to eliminate false positives and identify business logic flaws.

---

### [Week 06: Binary Analysis & Malware Triage](./week06/)
**Topics**: Static Analysis, PE Headers, IOC Extraction, YARA Rules

- Calculated cryptographic hashes (MD5, SHA1, SHA256) for IOC generation
- Extracted strings and analysed embedded artifacts
- Inspected PE file structure (entry points, imports, sections)
- Developed custom YARA rules for pattern detection
- Built integrated static analysis workflow
- [Hash Calculator](./week06/hash_calculator.py)
- [String Extractor](./week06/string_extractor.py)
- [PE Inspector](./week06/pe_inspector.py)
- [YARA Rule Engine](./week06/yara_scanner.py)
- [Complete Triage Workflow](./week06/static_triage.py)
- [Malware Analysis Report - Procmon.exe](./week06/analysis_report.md)

**Key Insight**: Static analysis provides a safe, efficient first-pass triage method. Suspicious API imports like `CreateRemoteThread` and `VirtualAllocEx` are strong indicators of process injection techniques used in malware.

---

### [Week 07: Penetration Testing](./week07/)
**Topics**: Reconnaissance, Port Scanning, Ethical Hacking Methodology

- Performed WHOIS domain lookups and passive reconnaissance
- Implemented custom port scanner in Python
- Utilised python-nmap for comprehensive service detection
- Documented black-box vs. white-box testing approaches
- Established ethical testing boundaries
   [Domain Reconnaissance Script](./week07/domain_recon.py)
- [Custom Port Scanner](./week07/port_scanner.py)
- [Nmap Integration](./week07/nmap_scanner.py)
- [Penetration Testing Methodology](./week07/pentest_methodology.md)
- [Ethical Guidelines Document](./week07/ethical_guidelines.md)

**Key Insight**: Reconnaissance is the most critical phase of penetration testing. The information gathered during passive reconnaissance (WHOIS, DNS, public records) can reveal attack surfaces without triggering defencive systems.

---

### [Week 09: Generative AI Security](./week09/)
**Topics**: LLM Vulnerabilities, Prompt Injection, Model Security

- Deployed local LLMs using Ollama (SmolLM2:1.7b, Llama variants)
- Tested prompt injection vulnerabilities (direct and indirect)
- Simulated data poisoning and observed model drift
- Explored model inversion and extraction techniques
- Compared security postures across multiple models
- Proposed comprehensive defence strategies
- [Ollama Deployment Scripts](./week09/ollama_setup.py)
- [Prompt Injection Tests](./week09/prompt_injection.py)
- [Data Poisoning Simulation](./week09/data_poisoning.py)
- [Model Extraction Experiments](./week09/model_extraction.py)
- [Multi-Model Comparison Report](./week09/model_comparison.md)
- [AI Security Defence Framework](./week09/defense_strategies.md)

**Key Insight**: Generative AI systems introduce novel attack surfaces distinct from traditional software vulnerabilities. Prompt injection can bypass safety measures even in well-designed systems, highlighting the need for defence-in-depth approaches including input sanitisation, output validation, and behavioural monitoring.

---

## 🔧 Key Skills Demonstrated

### Technical Competencies
- **Python Programming**: Advanced scripting for security automation
- **Cryptography**: RSA, AES, hybrid encryption schemes, padding mechanisms
- **Network Security**: Socket programming, protocol analysis, secure communication
- **Web Security**: Vulnerability scanning, OWASP methodology, injection attacks
- **Binary Analysis**: PE file parsing, string extraction, hash calculation, YARA rules
- **Penetration Testing**: Reconnaissance, port scanning, service enumeration
- **AI Security**: LLM deployment, adversarial testing, prompt engineering

### Professional Competencies
- **Documentation**: Clear, comprehensive technical writing
- **Ethical Practise**: Understanding legal and ethical boundaries in security testing
- **Analytical Thinking**: Root cause analysis, threat modelling, risk assessment
- **Tool Proficiency**: Wapiti, Nmap, pefile, YARA, Ollama, cryptography libraries
- **Research Skills**: Self-directed learning, literature review, emerging threat analysis

---

## Reflective Summary

### Overall Learning Journey

This module transformed my understanding of security from abstract principles to practical, hands-on capabilities. The progression from foundational concepts (Week 1: CIA Triad) through applied cryptography (Weeks 2-4), vulnerability assessment (Weeks 5-7), and emerging AI threats (Week 9) created a comprehensive security mindset.

### Key Challenges Overcome

1. **Cryptographic Implementation**: Initially struggled with proper padding schemes and key serialisation. Through experimentation and research into cryptographic standards (PKCS#8, OAEP), I gained confidence in implementing secure systems.

2. **Ethical Boundaries**: Understanding the legal implications of security testing required careful research. I established clear guidelines: only test systems I own or have explicit permission to test.

3. **Tool Integration**: Learning to combine multiple security tools (Wapiti, Nmap, YARA) into cohesive workflows required understanding both their capabilities and limitations.

### Most Impactful Learning

**Week 6 (Malware Analysis)** was transformative. Understanding how analysts extract IOCs from binaries and use them for threat hunting across an organisation revealed the practical side of incident response. The realisation that a single MD5 hash can help defenders identify infected systems across thousands of endpoints demonstrated the power of systematic analysis.

**Week 9 (AI Security)** was equally revelatory. Testing prompt injection attacks against local LLMs showed how new technologies introduce entirely new vulnerability classes. The ease with which safety measures could be bypassed reinforced that security must evolve alongside technology.

### Career Readiness

This portfolio directly addresses skills sought in cybersecurity job postings:
- **Security Analyst roles**: Vulnerability assessment, IOC extraction, YARA rules
- **Application Security**: Web vulnerability scanning, OWASP methodology
- **Incident Response**: Malware triage, hash calculation, threat intelligence
- **AI Security Specialist**: LLM vulnerability testing, prompt injection defence

### Areas for Future Development

1. **Dynamic Malware Analysis**: Extending static analysis skills to sandbox environments
2. **Exploit Development**: Understanding vulnerability exploitation to better defend against it
3. **Cloud Security**: Applying these principles to AWS/Azure environments
4. **Automation**: Building security pipelines for continuous monitoring

### Contribution to the Field

Through this work, I've developed:
- Reusable Python scripts for security automation
- Documentation templates for vulnerability reporting
- Ethical testing frameworks for emerging AI systems

---

## 📖 References

### Academic Sources
- Stallings, W. (2017). *Cryptography and Network Security: Principles and Practise* (7th ed.)
- OWASP Foundation. (2021). *OWASP Top Ten Web Application Security Risks*
- Sikorski, M., & Honig, A. (2012). *Practical Malware Analysis*

### Industry Standards
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- NCSC Annual Review 2021: https://www.ncsc.gov.uk/
- CVE Database: https://cve.mitre.org/

### Technical Documentation
- Python Cryptography Library: https://cryptography.io/
- YARA Documentation: https://yara.readthedocs.io/
- Ollama Documentation: https://github.com/ollama/ollama

### Tools Used
- Wapiti v3.x - Web Application Vulnerability Scanner
- Nmap v7.x - Network Mapper
- pefile - PE File Parser
- python-nmap - Python Nmap Integration
- Ollama - Local LLM Deployment Platform

---
