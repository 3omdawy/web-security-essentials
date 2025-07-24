# 🛡️ Web Security Essentials

A concise and practical guide to web security concepts, common attacks, and best practices.

## 📑 Table of Contents
- [Core Concepts](#-core-concepts)
- [Common Attacks](#-common-attacks)
- [Best Practices](#-best-practices)
- [Handling Sensitive Data](#-handling-sensitive-data)
- [Extra Layers of Protection](#-extra-layers-of-protection)
- [References & Resources](#-references--resources)
- [Infographic](#-infographic)

---

## 🔐 Core Concepts

### 🍪 Cookies
Cookies are used for user identification:
- **Stateful apps**: Store session IDs
- **Stateless apps**: Store JSON Web Tokens (JWTs)

---

## 🚨 Common Attacks

### 💉 SQL Injection
Attackers manipulate SQL queries to access or alter unauthorized data.

**Defenses**:
- Use **parameterized queries** or prepared statements and/or
- Avoid string concatenation in SQL queries. Use input escaping (i.e. replace each parameter with `?` and pass as an arguments to the query)

---

### 👆 Privilege Escalation
Attackers inject unexpected fields (especially with PATCH/PUT) to escalate access or privileges.

**Defenses**:

**Whitelist allowed fields** in updates (Do not blindly merge user input with database objects)

---

### 📂 File Upload Vulnerabilities
- Uploading malicious files (e.g., scripts or zip bombs) disguised as harmless files (e.g. as a profile photo)
- Then, the attacker can execute this malicious file on the server

**Defenses**:
- **Validate MIME types and file extensions.** Ensure only trusted file types can be uploaded
- Enforce access control on uploaded files (prevent unauthorized access to uploaded files)
- Sanitize file names
- Use unique and unpredictable storage paths

---

### 🎃 Cross-Site Request Forgery (CSRF)
Attackers trick authenticated users into submitting unwanted actions (when the user goes to the attacker’s website) — e.g. auto-submit a form that transfers money to another account.

**Defenses**:
- Set cookies with `SameSite=Lax` or `Strict`
- Use **CSRF tokens** in forms and requests: Generate a unique token per session (as a hidden form field or another cookie) that validates that this is a legitimate request
- Use UX methods for protection:
    - Require re-authentication for sensitive actions
    - Implement 2FA or confirmation steps when needed

---

### 😈 Cross-Site Scripting (XSS)
Attackers inject malicious scripts into trusted sites (e.g. by filling an input field like a comment on an article with malicious script).

**Types**:
- **Stored**: Persisted on the backend (e.g. DB)
- **Reflected**: Comes from URL or query param
- **DOM-based**: Executed via client-side JS

**Defenses**:
- **Sanitize and escape all user-generated content**
- Use safe template engines that escape output. Use libraries like `DOMPurify`
- Apply a strict Content Security Policy (CSP)
- Use safe methods in which the browser will never execute code (e.g. `element.textContent` instead of `element.innerHTML`)

---

## 🎁 Best Practices

### 🧼 Sanitize Input
Validate and sanitize all user input on both frontend and backend.

---

### 🍪 Cookie Attributes Cheat Sheet

| Attribute   | Purpose                                      | Value |
|------------|---------------------------------------------- | ----- |
| `signed`   | Detect tampering in the backend               | true  |
| `httpOnly` | Prevent access from JavaScript (XSS defense)  | true  |
| `secure`   | Send only over HTTPS                          | true  |
| `sameSite` | Restrict cross-origin requests (CSRF defense) | Strict or Lax |
| `maxAge`   | Set explicit expiration                       | e.g. 1 hr |
| `domain`   | Avoid using sub-domains unless you own the domain | e.g. without a preceding `.` |

🚫 **Never store sensitive data (e.g., passwords or credit cards) in cookies or JWTs** — they are not encrypted by default.

---

## 🔒 Handling Sensitive Data

- Hash passwords using a secure algorithm (e.g., bcrypt) with salt.
- Encrypt sensitive data (e.g., credit cards) using trusted libraries
- Keep encryption keys secure and out of source control
- Always use HTTPS in production
- Never include sensitive data in URLs (query params are stored in browser history)
- Do not log sensitive information

---

## 🛡️ Extra Layers of Protection

### 🧱 CORS (Cross-Origin Resource Sharing)
Restricts which origins can interact with your server.

**Best Practices**:
- Only allow trusted domains
- Avoid `Access-Control-Allow-Origin: *` for private APIs

---

### 📜 CSP (Content Security Policy)
Restricts resource loading (e.g., scripts, fonts, styles) to trusted sources.

**Example**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com
```

ℹ️ Note: CSP also protects against **clickjacking attack 👆**.

## 📚 References & Resources
- [Web Security: Browser security fundamentals | Protect against CSRF, XSS, & SQL Injection | Frontend Masters](https://frontendmasters.com/courses/web-security-v2/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Web.dev Secure Sites](https://web.dev/explore/secure)

## 📊 Want a visual version?
![Web Security Infographic](<Web Security.png>)