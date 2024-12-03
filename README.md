# Advanced Email Threat Hunting w/ Detection as Code

---

## 📖 Overview

Email remains one of the most common cyberattack vectors, making email threat hunting a vital skill for security professionals. While tools like secure email gateways and provider-level protections (e.g., Office 365, Google Workspace) catch obvious threats, advanced phishing, spoofing, and sophisticated attacks often slip through.

Sublime enhances your detection capabilities with robust features, including organizational context, historical insights, and behavioral baselines; offering significantly more than standard EML analyzers. With Sublime, you get:

- A **30-day historical data ingestion**, paired with a **14-day free trial**, for a comprehensive 44-day analysis window
- A **free managed tier** for up to **100 mailboxes**, ideal for smaller organizations or a representative subset of critical/highly targetted user mailboxs

By the end of this workshop, you’ll learn how to:
- Use Sublime's **Message Query Language (MQL)**
- Proactively identify and respond to email threats with hands-on examples
- Continue hunting with additional resources

---

## ✉️ Sublime Email Analyzer (No Installation Required)

### ➡️ Quickly analyze suspicious emails with the **[EML Analyzer](https://analyzer.sublime.security/)**

- **What it does**: Parses and enriches raw email messages into a structured schema, the **Message Data Model (MDM)**, and runs detection rules using Sublime's **MQL**
- **What it’s for**: Investigate suspicious or user-reported emails without needing full platform integration

For advanced analysis with added organizational context, follow the **Advanced Setup** below.

---

## ⚙️ Advanced Setup (Optional)

### Prerequisites
- Active subscription to **Office 365** or **Google Workspace**
- Administrator access to your organization's email environment
- A Sublime account ([Sign up here](https://sublime.security/start/))

### ⚡ Setup for Office 365 

1. Log in to the **Microsoft Office Admin Console**.
2. Follow the link here, or continue with the step-by-step setup guide inside of Sublime: [Installation for Office 365](https://docs.sublime.security/docs/installation).
3. Navigate to **Admin → Message Sources** in Sublime and add a new message source.
4. Approve the **Graph API Connector** to establish the connection.

### ⚡ Setup for Google Workspace

1. Log in to the **Google Workspace Admin Console**.
2. Follow the link here, or continue with the step-by-step setup guide inside of Sublime: [Installation for Google Workspace](https://docs.sublime.security/docs/installation).
3. Navigate to **Admin → Message Sources** in Sublime and add a new message source.
4. Complete the connection by adding the private **Google Workspace Marketplace App** [here](https://workspace.google.com/marketplace/app/sublime_cloud_platform/421484249706).

Once connected, Sublime is ready for comprehensive email threat hunting.

---

## 💡 Tips and Tricks

Start with the most broad query that will flag on your example. Sometimes a complex rule is needed for a specific scenario, but often the best rule, is the most simple you can get away with!

Use existing rules in the [Sublime Core Feed](https://sublime.security/feeds/core/?page=1&view=list) or [Common snippets](https://docs.sublime.security/docs/common-snippets) to fit the conditions you are attempting to flag on.

---

## 🧪 Examples

Practice threat hunting with these scenarios. Use the hidden solutions to verify your work only after attempting the queries. There will always be more than 1 correct answer!

### Example 1: Detecting Suspicious Senders
Identify emails sent from domains resembling your company’s.

<details>
  <summary>Solution</summary>

  ``` yaml
  FROM addresses CONTAINING domain SIMILAR TO "yourdomain.com"
