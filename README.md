# Email Threat Hunting with Sublime

## Overview

Email remains one of the most common vectors for cyberattacks, making effective email threat hunting an essential skill for security professionals. While traditional email filtering solutions such as secure email gateways and provider-level protections (e.g., Office 365 or Google Workspace) do a decent job at catching obvious threats, advanced phishing, spoofing, and other sophisticated attacks can often evade detection.

Sublime provides a robust platform for identifying, investigating, and remediating these threats with precision and efficiency. Its powerful query language and seamless integration with email platforms make it an invaluable tool for security teams looking to enhance their threat hunting capabilities.

By the end of this project, you'll learn how to set up Sublime with popular email providers and develop practical skills to proactively identify and respond to email threats.

---

## Setup

### Prerequisites
- An active subscription to either **Office 365** or **Google Workspace**
- Administrator access to your organization's email environment
- A Sublime account ([Sign up here](https://www.sublime.security/))

### 1. Setting up Sublime with Office 365

1. Log in to the **Microsoft 365 Admin Center**.
2. Register Sublime as an application in Azure Active Directory:
   - Navigate to `Azure Active Directory > App Registrations`.
   - Select **New Registration** and follow the prompts.
3. Assign appropriate API permissions for email access (e.g., `Mail.Read`).
4. Generate a client secret and note the **App ID**, **Tenant ID**, and **Client Secret** for later use.
5. Connect Sublime to Office 365 by following the detailed guide [here](https://docs.sublime.security/docs/office365).

### 2. Setting up Sublime with Google Workspace

1. Log in to the **Google Workspace Admin Console**.
2. Enable API access:
   - Navigate to `Security > API Controls > Enable API Access`.
3. Set up a service account in Google Cloud Platform:
   - Go to the [Google Cloud Console](https://console.cloud.google.com/).
   - Create a new project and enable the Gmail API.
   - Configure a service account with the required permissions.
4. Connect Sublime to Google Workspace by following the detailed guide [here](https://docs.sublime.security/docs/google-workspace).

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
