# SecureShield: Gateway-Based Defense Against Fake Banking Apps

**A layered system that detects and blocks fake banking app threats before they can harm users.**

---

## 🛡️ About The Project
India loses over ₹10,000 crore annually to cyber fraud, with SBI being the most impersonated bank. SecureShield addresses this crisis by offering a comprehensive, multi-layered defense architecture. Unlike traditional single-layer detection tools that act *after* installation, SecureShield intercepts threats proactively at the gateway level, device level, and human layer.

**Threat Landscape Addressed:**
- 📱 **Phishing Links (SMS/WhatsApp):** 40%
- 📞 **Phone / Social Engineering:** 30%
- 📦 **Malicious APK Installs:** 20%
- ❓ **Others:** 10%

---

## 📸 Screenshots


<div align="center">
  <img src="Screenshot from 2026-06-02 20-29-41.png" alt="Gateway Interception Screen" width="200"/>
  <img src="Screenshot from 2026-06-02 20-29-54.png" alt="Live Threat Monitoring Dashboard" width="200"/>
</div>

---

## 🎯 Core Objectives
1. **Intercept Malicious Links:** Block phishing URLs directly at the gateway.
2. **Prevent Fake APK Installation:** Check signatures and permissions before an app can install.
3. **Detect Device-Level Threats:** Spot droppers, screen-sharing exploitation, and fake apps.
4. **Guard Against Social Engineering:** Verify incoming callers against active fraud databases.

---

## ⚙️ Architecture & Attack Pipelines

SecureShield relies on six critical defense pipelines to neutralize threats from various attack vectors:

### 1. Gateway Interception
Filters traffic before the browser loads a tapped URL. Utilizes rules-based filtering combined with an AI phishing model for high-accuracy threat scoring.

### 2. APK Verification
Intercepts APK files arriving through any channel. Performs signature verification (against official certificates) and flags dangerous permission requests.

### 3. Human Layer Protection
Matches inbound communication (Calls/SMS) against live fraud numbers, providing immediate warnings on a fraud match.

### 4. Remote Access Monitoring
Detects active remote or screen-sharing sessions, prompting the user and classifying the risk appropriately based on the session state.

### 5. Behavior Monitoring
Scans applications at runtime and installation. Flags abusive overlay or SMS permissions and matches app behaviors against known dropper profiles.

### 6. Deep Scan
Compares installed applications against official SBI/YONO packages. Identifies invalid certificates, signature mismatches, and fake branding.

---

## 🧠 AI-Powered Intelligence Layer
SecureShield utilizes Machine Learning to adapt to novel threats beyond rule-based detection:
- **AI Phishing Detection:** Scores URLs using lexical, domain, redirect, and visual signals to catch zero-day phishing.
- **NLP Fraud Message Analysis:** Flags SMS and WhatsApp scams by analyzing urgency, impersonation, and OTP request patterns.
- **Continuous Pattern Learning:** Constantly retrains to adapt quickly to evolving fraud tactics.

---

## 🚀 Why SecureShield Outperforms Existing Solutions
* **Gateway + Device + Human Defense:** Complete protection covering pre-click, post-install, and social vectors.
* **Pre-Click Interception:** Stops threats *before* the browser or filesystem is involved.
* **No Single Point of Failure:** A layered fallback system ensures that if one layer is bypassed, the next neutralizes the attack.

---

## ⚠️ Challenges & Limitations
* **Pre-Compromised Devices:** SecureShield cannot fully trust its execution environment if the device is already compromised.
* **Fabricated / Modified OS:** Custom ROMs can weaken gateway interception and spoof permissions.
* **Cross-Platform Restrictions:** iOS limits gateway control, making feature parity with Android challenging. Full prevention in highly adversarial OS environments remains an open research problem.

---

## 🔮 Future Roadmap
* Hardware-backed attestation to ensure device integrity.
* Expanded iOS support for comprehensive cross-platform protection.
* A federated fraud database.
* Collaboration with **CERT-In** and **RBI** for real-time threat intelligence sharing and model training.

