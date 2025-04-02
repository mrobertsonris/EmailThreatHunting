EmailThreatHunting

# Advanced Email Threat Hunting w/ Detection as Code

![Banner](https://github.com/user-attachments/assets/cf9f3e05-6b39-447c-8739-6d0226fd5e8e)

---

## ‼️ Disclaimer
This project is provided "as-is" without any guarantee of updates or maintenance. Please note that some samples included may contain malicious links or attachments. By using this repository, you agree to handle all materials responsibly and understand the associated risks. The authors are not liable for any misuse or consequences resulting from the use of this project.

## 📖 Overview

Email remains one of the most common cyberattack vectors, making email threat hunting a vital skill for security professionals. While tools like secure email gateways and provider-level protections (e.g., Office 365, Google Workspace) catch obvious threats, advanced phishing, spoofing, and sophisticated attacks often slip through.

[Sublime Security](https://sublime.security/) enhances your detection capabilities with robust features, including organizational context, historical insights, and behavioral baselines; offering significantly more than standard EML analyzers. With Sublime, you get:

- A **30-day historical data ingestion**, paired with a **14-day free Enterprise trial**, for a comprehensive 44-day analysis window
- A **free managed tier** for up to **100 mailboxes**, ideal for smaller organizations or a representative subset of critical/highly targetted user mailboxes
- **Free self-managed** deployments are available via Docker (**600 mailboxes**), AWS CloudFormation, and Azure ARM

By the end of this workshop, you’ll learn how to:
- Use Sublime's **Message Query Language (MQL)**
- Proactively identify and respond to email threats with hands-on examples
- Continue hunting with additional resources and **[Detection Rules based on the examples in this workshop](https://github.com/mrobertsonris/EmailThreatHunting/tree/main/detection-rules)**

---

## 📨 Sublime Email Analyzer (No Installation Required)

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

## 🔗 Useful Links

- [EML Analyzer](https://analyzer.sublime.security/)
- [Sublime Core Feed](https://sublime.security/feeds/core/?page=1&view=list)
- [MQL Syntax](https://docs.sublime.security/docs/syntax)
- [Common snippets](https://docs.sublime.security/docs/common-snippets)
- [YARA Rules](https://docs.sublime.security/docs/yara)
- [Answer Bank (SPOILERS!)](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Answer%20Bank.md)

**How-To MQL Guides**
- [How to detect keywords or phrases in the body content of messages](https://docs.sublime.security/docs/how-to-detect-keywords-or-phrases-in-the-body)
- [How to detect text in attachments](https://docs.sublime.security/docs/how-to-detect-text-in-attachments)

**Additional Learning Resources**
- [Sublime Email Detection Engineering and Threat Hunting Labs](https://labs.sublime.security/)
- [Sublime Blog](https://sublime.security/blog/)
- [Sublime Community Slack](https://join.slack.com/t/sublimecommunity/shared_invite/zt-2pgrmaiv7-~P4w6t9JEJO7NenHCdriDA)

**CISA Secure Cloud Business Applications (SCuBA) Project**
- [SCuBA](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)

---

## 💡 Tips and Tricks

Start with the most broad query that will flag on your example. Sometimes a complex rule is needed for a specific scenario, but often the best rule, is the most simple you can get away with!

Use existing rules in the [Sublime Core Feed](https://sublime.security/feeds/core/?page=1&view=list) or strings from [Common snippets](https://docs.sublime.security/docs/common-snippets) to fit the conditions you are attempting to flag on.

---

## 🧪 Examples

Practice threat hunting with these scenarios. Use the hidden solutions to verify your work only after attempting the queries. I will give what I think is good detection logic, but there will always be more than 1 correct answer as you may see a different way forward! 

### 🏹 Completing each example will unlock the next. Happy hunting!

### Example 1: DIRECT DEPOSIT CHANGE -- [Download Sample .eml Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/DIRECT%20DEPOSIT%20CHANGE.eml)
Payroll fraud involving employee spoofing occurs when an attacker impersonates an employee to request changes to their direct deposit details, diverting funds to the attacker’s account. This is typically done through phishing emails, social engineering, or forged documents. It can result in financial loss, employee distress, and reputational damage if not promptly detected and mitigated.


<details>
  <summary>Hint</summary>

  ``` txt
  Consider creating a string or regex detection for some of the keywords present in the subject or body text.
  ```

<details>
  <summary>Solution</summary>

  ``` yml
type.inbound
and 1 of (
  regex.icontains(body.current_thread.text,
                  '(pay\s?(roll|check|date|day)|direct deposit|\bACH\b|\bdd\b|gehalt|salario|salary)'
  ),
  regex.icontains(subject.subject,
                  '(pay\s?(roll|check|date|day)|direct deposit|\bACH\b|\bdd\b|gehalt|salario|salary)'
  ),
  // request
  (
    any(ml.nlu_classifier(body.current_thread.text).entities,
        .name == "request"
    )
    // financial
    and any(ml.nlu_classifier(body.current_thread.text).entities,
            .name == "financial"
    )
  )
)
  ```

### Example 2: Jamie sent you a file -- [Download Sample .eml Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/Jamie%20sent%20you%20a%20file.eml)
Attackers exploit free form submission and collaboration tools like Google Drawings to conduct chainlink phishing attacks by hosting malicious content on these trusted platforms. They craft phishing emails that direct recipients to seemingly legitimate documents or graphics hosted on services like Google Drawings, which contain embedded malicious links. This strategy leverages the inherent trust in well-known platforms to bypass security filters and deceive users into clicking on harmful links, leading to credential theft or malware installation. 


<details>
  <summary>Hint</summary>

  ``` txt
  Free form submission and collaboration tools are often used for chainlink phishing. In this case, the attacker appears to be using a fake image in a Google drawing. Can you detect for the use of a Google drawings link or current thread text?
  ```

<details>
  <summary>Solution</summary>

  ``` yml
type.inbound
and (
  strings.icontains(body.current_thread.text, "docs.google.com/drawings/")
  or any(body.links,
         strings.ilike(.href_url.url, "*docs.google.com/drawings/*")
  )
)
  ```

### Example 3: Removed at request of BEC third party.

### Example 4: One pkg to rule them all -- [Download Sample .eml Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/One%20pkg%20to%20rule%20them%20all.eml)
Malicious OneNote files are used in phishing emails to deliver malware by embedding malicious scripts or links within the file. These emails often impersonate trusted contacts or organizations to trick users into opening the file and triggering the malware. This can lead to further phishing, device compromise, data theft, or the spread of ransomware.


<details>
  <summary>Hint</summary>

  ``` txt
  Try to create a detection looking for the presence of a onenote file.
  ```

<details>
  <summary>Solution</summary>

  ``` yml
type.inbound
and (
  any(attachments,
      .file_extension in~ $file_extensions_common_archives
      and any(file.explode(.),
              .depth > 0
              and .file_extension in~ (
                "onenote", // Microsoft OneNote notebook file
                "one", // Microsoft OneNote section file
                "onepkg", // Microsoft OneNote package file
              )
      )
  )
  or any(attachments,
         .file_extension in~ (
           "onenote", // Microsoft OneNote notebook file
           "one", // Microsoft OneNote section file
           "onepkg", // Microsoft OneNote package file
         )
  )
)
  ```

### Example 5: eMail Account Suspention Notice -- [Download Sample .eml Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/eMail%20Account%20Suspention%20Notice.eml)
Newly registered domains (NRDs) are often used in malicious email attacks because they are unlikely to be flagged by security systems due to their lack of history or reputation. Attackers use these domains to impersonate trusted organizations, send phishing emails, or host malicious content, such as fake login pages or malware. Their short lifespan and ability to bypass filters make NRDs a powerful tool for delivering credential theft and malware attacks.


<details>
  <summary>Hint</summary>

  ``` txt
  Consider the insights that triggered here. Can you create a detection with whois data for a domain that is less than 30 days old?
  ```

<details>
  <summary>Solution</summary>

  ``` yml
type.inbound
and any(body.links, network.whois(.href_url.domain).days_old <= 30)
  ```

### Example 6: Ajith Babu Salary New Bonus 2024-2025.pdf -- [Download Sample Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/sample-1561072-71fa2fea553b9df8eab077f6b5af3ed7.zip)
For this sample you'll need to build an .eml with the Sublime analyzer. I've predownloaded the file so that it will remain available. Once you have the .zip file of the malware sample downloaded, extract the PDF contained. Using the Sublime EML Analyzer, "Build an EML", and add the PDF as an attachment. **Sample (pw = infected)**
- [JoesSandbox Windows Analysis Report](https://www.joesandbox.com/analysis/1561072/0/html)

Fake PDF files with malicious links are used in phishing attacks to trick recipients into clicking links that lead to credential theft or malware downloads. These files are often disguised as legitimate documents from trusted sources, exploiting the perceived safety of PDFs to bypass user suspicion. This threat highlights the importance of scrutinizing unexpected attachments and using advanced email security to detect malicious activity.

<details>
  <summary>Hint</summary>

  ``` txt
  Explore the screenshots of the PDF file being executing in JoeSandbox as well as the insights and links. 
  ```

<details>
  <summary>Solution</summary>

  ``` yml
type.inbound
and any(attachments,
        .file_extension == "pdf"
        and any(file.explode(.),
                any(.scan.pdf.urls,
                    regex.contains(.path, '\.(?:html|xhtml|shtml|htm|)\b')
                )
                and any(ml.nlu_classifier(.scan.ocr.raw).intents,
                        .name == "cred_theft"
                        and .confidence in~ ("medium", "high")
                )
        )
)
  ```

### Example 7: Сhеϲk Νеԝ Αdjυѕtⅿеntѕ Rеⅼеаѕеd! Rеvіеԝ аnd ϲⅼаіⅿ уουr Βеnеfіt/Βοnυѕ fοr Μаіⅼοnⅼіnе Αϲtіvіtіеѕ 4th Qυаrtеr - ΙуΝՍRᏙhՍΤⅼᏙΝՍkFΟRΕ9ΝΟᎠΑjΙԝ== -- [Download Sample Here](https://github.com/mrobertsonris/EmailThreatHunting/blob/main/Example%20Emails/3e5cb809-f546-fb3c-b0e3-5de228b453ab.eml.zip)
This is a great example of responding to OSINT by hunting, then creating a new detection. This was performed by the Sublime team just a few hours after the technique was observed in the wild!

I've predownloaded the file so that it will remain available. Once you have the .zip file of the malware sample downloaded, extract and upload to the Sublime EML Analyzer. **Sample (pw = infected)**

- [Original Any Run OSINT](https://x.com/anyrun_app/status/1861024182210900357)
- [Bleeping Computer OSINT](https://www.bleepingcomputer.com/news/security/novel-phishing-campaign-uses-corrupted-word-documents-to-evade-security/)

- [Any Run Sandbox](https://app.any.run/tasks/6839e806-56b6-4504-99a4-cc41c9b509df/?utm_source=twitter&utm_medium=post&utm_campaign=corrupted_files&utm_term=251124&utm_content=linktoservice#)

- [Sublime Core Feed - MALFORMED_OLE_HEADER YARA Rule](https://github.com/sublime-security/sublime-rules/blob/5f3632e47b5fb5f857ded52d010eb096f5c2638f/yara/malformed_ole_header.yar#L4)
- [Sublime Core Feed - Attachment: Malformed OLE file](https://github.com/sublime-security/sublime-rules/blob/5f3632e47b5fb5f857ded52d010eb096f5c2638f/detection-rules/attachment_malformed_ole.yml)

Attackers use intentionally corrupted Word documents in phishing emails to evade security filters. When recipients attempt to repair the document, malicious content is executed, enabling credential theft or malware installation. This tactic exploits trust in document recovery features to increase attack success.

## 🎉 Congratulations! You've completed the "Advanced Email Threat Hunting w/ Detection as Code" workshop. Use your newly aquired skills and go catch some bad guys. Happy hunting!

**[Detection Rules based on the examples in this workshop](https://github.com/mrobertsonris/EmailThreatHunting/tree/main/detection-rules)**

**Add this repo as a "Feed" in Sublime as an alternative to manually hunting with each rule individually.**


