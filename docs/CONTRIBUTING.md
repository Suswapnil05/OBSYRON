# Contributing to OBSYRON XTM 2.0

Thank you for your interest in contributing to OBSYRON! We welcome contributions from cybersecurity researchers, forensic engineers, frontend developers, and data scientists.

---

## 1. Code of Conduct & Scope

OBSYRON is strictly a **defensive cyber-forensic investigation platform**.
- **Prohibited:** Any PR containing active exploitation tools, malicious payloads, credential harvesters, or unauthorized scanning utilities will be rejected immediately.
- **Encouraged:** Enhancements to log parsers, clock drift heuristics, graph theory algorithms, MITRE technique definitions, and forensic reporting.

---

## 2. Development Workflow

1. **Fork the Repository:** Fork to your GitHub account and clone locally.
2. **Create a Feature Branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```
3. **Set Up Development Environment:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Implement & Test:**
   - Write your enhancements cleanly following PEP 8 conventions.
   - Run the automated test suites:
     ```bash
     python test_direct_endpoints.py
     python test_obsyron.py
     ```
5. **Commit & Push:**
   - Use Conventional Commits (`feat: ...`, `fix: ...`, `docs: ...`).
6. **Submit Pull Request:** Detail the problem solved and include verification screenshots.

---

## 3. Style & Standards

- **Python:** Black formatting, type hints where appropriate, clean docstrings.
- **Frontend:** Semantic HTML5, accessible ARIA labels, clean CSS variables adhering to the Filigran dark SOC palette.
- **Zero Hallucination:** Any new narrative generation must link to verifiable `log_id` citations in the Evidence DNA ledger.

