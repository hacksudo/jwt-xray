# 🛡 Hacksudo JWT X-Ray

> 🔎 JWT Inspection, Analysis, Builder & Lightweight Request Modifier for Firefox  
> Built by **Vishal Waghmare** — https://hacksudo.com  

---

## 🚀 Overview

**Hacksudo JWT X-Ray** is a powerful Firefox extension designed for:

- 🧑‍💻 Bug bounty hunters  
- 🔐 Pentesters  
- 👨‍🎓 Security students  
- 🧑‍🔬 API developers  

It provides real-time JWT detection, decoding, risk analysis, token editing, re-encoding, and rule-based request modification — directly inside your browser.

> ⚡ Think of it as: “JWT Burp Lite inside Firefox”

---

## ✨ Features

### 🔍 Automatic JWT Detection
- Detects JWT from:
  - Authorization headers
  - Cookies
  - LocalStorage
  - SessionStorage
- Stores detected tokens in history

---

### 🧠 Smart Security Analysis
Checks for:

- `alg=none`
- Missing `exp`, `iat`, `iss`, `aud`
- Expired tokens
- Long-lived tokens
- Sensitive claims (`admin`, `role`, `scope`, `permissions`)

Risk Levels:
- 🟢 Low  
- 🟡 Medium  
- 🔴 Critical  

---

### 🧩 Token Builder (Edit + Re-Encode)
- Edit Header & Payload JSON
- Re-encode unsigned tokens
- Re-sign using:
  - HS256
  - HS384
  - HS512
- Copy / Save / Load into decoder

⚠️ Intended for authorized security testing only.

---

### 🔄 Token Compare
- Compare payload differences between two tokens
- Highlight changed claims
- Useful for privilege escalation testing

---

### 📜 Rule-Based Request Modifier
Create URL-based rules to:

- Set `Authorization: Bearer <token>`
- Inject cookies (`key=value`)
- Match by:
  - contains
  - startsWith
  - regex

Helps test authentication flows without using an external proxy.

---

### 🗂 Token History
- Stores last 50 detected tokens
- Shows:
  - Source
  - URL
  - Timestamp
- Click to instantly load into decoder

---

## 🛠 Installation (Development Mode)

1. Clone repository:

```bash
git clone https://github.com/hacksudo/jwt-xray.git
cd jwt-xray
```

## Open Firefox
```bash
about:debugging
Click --> This Firefox → Load Temporary Add-on
Select --> manifest.json
Open Sidebar --> View → Sidebar → Hacksudo JWT X-Ray
```

## 📁 Project Structure
```bash
hacksudo-jwt-xray/
│
├── manifest.json
├── background.js
├── content_script.js
│
├── sidebar/
│   ├── sidebar.html
│   ├── sidebar.css
│   └── sidebar.js
│
└── icons/
    └── icon.svg
```

## 🔒 Security & Usage Disclaimer
` ⭐ Support ` 
If you find this useful:

` ⭐ Star the repository` 
Share with the security community
Submit improvements via Issues

## 🎯 Roadmap
`Planned improvements:`
DevTools integration panel
Per-domain JWT dashboard
Exportable security report (JSON/Markdown)
Auto rule creation from Builder
Enhanced UI & theme modes

## ⭐ Support
If you find this useful:
`⭐ Star the repository`
Share with the security community
Submit improvements via Issues

## 🎯 🧑‍💻 Author
Vishal Waghmare
Cybersecurity Engineer
🌐 https://hacksudo.com


