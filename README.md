# Email Threat Hunting with Sublime

## Overview

Email remains one of the most common vectors for cyberattacks, making effective email threat hunting an essential skill for security professionals. While traditional email filtering solutions such as secure email gateways and provider-level protections (e.g., Office 365 or Google Workspace) do a decent job at catching obvious threats, advanced phishing, spoofing, and other sophisticated attacks can often evade detection.

Sublime provides a robust platform for identifying, investigating, and remediating these threats with precision and efficiency. Its powerful query language and seamless integration with email platforms make it an invaluable tool for security teams looking to enhance their threat hunting capabilities.

By the end of this workshop, you'll learn how to set up Sublime with your email providers and develop practical skills to proactively identify and respond to email threats.

---

## Sublime Email Analyzer

**EML Analyzer [here](https://analyzer.sublime.security/).**

Automatically analyze any EML to quickly investigate suspicious or user reported emails.

Run the full Sublime platform using the below **Advanced Setup** for a complete analysis that includes organizational context, history, and behavioral baselines that the EML Analyzer doesn't have.

How does it work?
The EML Analyzer parses and enriches raw email messages into a structured schema, the Message Data Model (MDM), and then analyzes that MDM using detection rules written in Message Query Language (MQL). The Analyzer runs all detection rules present in the Sublime Core Feed.

---

## Advanced Setup -- (Optional)

### Prerequisites
- An active subscription to either **Office 365** or **Google Workspace**
- Administrator access to your organization's email environment
- A Sublime account ([Sign up here](https://sublime.security/start/))

### 1. Setting up Sublime with Office 365

1. Log in to the **Microsoft Office Admin Console**.
2. Connect Sublime to Office 365 by following the detailed guide [here](https://docs.sublime.security/docs/installation).
3. Add a new message source under **Admin -> Message Sources**.
4. Follow the prompts. Sublime will automatically add the **Graph API Connector** once approved.

Once the setup is complete, you can begin leveraging Sublime's capabilities for email threat hunting.

### 2. Setting up Sublime with Google Workspace

1. Log in to the **Google Workspace Admin Console**.
2. Connect Sublime to Google Workspace by following the detailed guide [here](https://docs.sublime.security/docs/installation).
3. Add a new message source under **Admin -> Message Sources**.
4. Follow the prompts. Sublime will require you to add the private **Google Workspace Marketplace App** to complete the connection [here](https://workspace.google.com/marketplace/app/sublime_cloud_platform/421484249706).

Once the setup is complete, you can begin leveraging Sublime's capabilities for email threat hunting.

---

## Examples

Below are some sample scenarios to help you practice email threat hunting. Each scenario includes hidden solutions to test your skills. Click the spoiler tags to reveal the answers only after attempting the exercises.

### Example 1: Detecting Suspicious Senders
You receive reports of suspicious emails in your organization. Use Sublime to identify emails sent from domains similar to your company's.

<details>
  <summary>Solution</summary>

  ```sql
  FROM addresses CONTAINING domain SIMILAR TO "yourdomain.com"
