---
title: Anonymous Azure Services Enumeration
date: 2026-08-06 00:00:00 +0000
categories: [OFFENSIVE AZURE, RECONNAISSANCE]
tags: [Azure, recon, offensive]
---

## Azure Enumeration

There are several ways to enumerate an Azure environment:

- **Authenticated** (with valid credentials)
- **Anonymously** (with no authentication at all)

The second approach is the one we'll explore here.

---

## Anonymous Azure Storage

A recurring problem on Azure? Publicly exposed storage accounts.
Yes, just like the infamous S3 buckets on AWS, but the Microsoft edition.

Every **"Storage Account"** is assigned a unique subdomain on `core.windows.net`.

> **Example:** I create the account `confidential-project`, and it becomes reachable at `confidential-project.core.windows.net`.
> The problem? If you leave access open, anyone can go digging through it.

And believe me, it happens more often than you'd think.

---

## Blobs

In this post, we'll focus mostly on **Blobs**, even though the other data types deserve some attention too.

Put simply, a Blob in Azure is storage for **unstructured** data. They're often used to serve public files (images, CSS, that kind of stuff). But here's where it gets spicy: you also find some filled with **sensitive** material:

- Configuration files
- Database backups
- Credentials / passwords

In short, the kind of folder you'd really like to keep under lock and key.
And to give you an idea of the scale: **Google alone indexes around 1.2 million PDFs** on the `blob.core.windows.net` subdomain. Yes, you read that right. 1.2 million.
It's safe to say the attack surface is very real.

`site:blob.core.windows.net`

---

## Permissions

Let's talk about permissions, because that's where everything is decided.
Blobs are stored in "Containers". To keep it simple, think of them as folders on your computer. Nothing fancy.
But here's where it gets interesting: every container has an access policy. And that policy decides one crucial thing: who can see your files?

- Can only you access them?
- Can anyone on the Internet read them?
- Can anyone even list the entire contents of the folder?

And guess what? If you pick the overly permissive option (and believe me, it happens more often than you'd think), your data becomes accessible to everyone. No password, no login, nothing.
In short: a misconfigured container is like leaving your apartment door wide open with a sign saying "Come in, everything's free."
And that's where things get truly dangerous, because you sometimes find very sensitive stuff in these blobs. But we'll come back to that later.

---

## Automation: a tool that does the work for us

With the growing number of Azure environments we come across in our audits, we quickly realized we needed to **automate** the search for publicly exposed blobs. Because doing it by hand? No thanks. 😅
Luckily, the team at NetSPI had already thought of everything. They released a PowerShell tool (we're in Microsoft land, after all), but honestly, the script could be rewritten in other languages without much difficulty.

> 📦 **The code is available here:**
> [NetSPI/MicroBurst on GitHub](https://github.com/NetSPI/MicroBurst)

---

### How does it work, concretely?

The tool does three main things:

**1. It hunts for valid storage accounts**
It starts by making DNS requests against the `blob.core.windows.net` subdomain. Basically, it tests potential account names to see whether they exist.

**2. It brute-forces container names**
Once it has found a storage account, it tries to enumerate the containers using the Azure Blob Service REST APIs. It tries names like `dev`, `test`, `qa`, in short, anything that looks like a folder name an admin might have left lying around.

**3. It uses the Bing API (optional)**
Since Google has already indexed millions of files, the tool can also query Bing to find containers that are already publicly exposed. One well-aimed search, and there you go.

### And once it finds a container?

It uses the Azure APIs again to check whether the container is in **"Container"** mode (the one that lets you list all the files). If it is, bingo: you can grab everything.

### Where does this idea come from?

The concept, as well as part of the permutation list, is directly inspired by a similar tool for AWS S3: **inSp3ctor**. But since we're on Azure, the team adapted everything to fit the Microsoft ecosystem.

**In summary:** a tool that does the dirty work for us, so we can focus on what's really interesting: the data people leave lying around. And frankly, given the number of exposed accounts we find, it runs a lot.

---

## Using the script

The script is called **`Invoke-EnumerateAzureBlobs`**, and it's pretty easy to pick up.
It accepts **five parameters**, which I'll detail below:

| Parameter | Description |
|-----------|-------------|
| `-Base` | The base name to apply the permutations to. Example: `netspi` |
| `-Permutations` | The file containing the words to add to the base name to find storage accounts (e.g. `dev`, `test`, `qa`). This gives you things like `netspidev`, `testnetspi`, etc. |
| `-Folders` | The file containing the potential folder names to brute-force (e.g. `files`, `docs`, `backup`). |
| `-BingAPIKey` | (Optional) The Bing API key used to find files that are already publicly indexed. |
| `-OutputFile` | The file where the results are written. |

### Usage example

```powershell
Invoke-EnumerateAzureBlobs -Base "contoso" -Permutations .\perms.txt -Folders .\folders.txt -OutputFile .\results.txt
```

## Additional resources

- <https://learn.microsoft.com/en-us/previous-versions/azure/cloud-services/cloud-services-choose-me>
- <https://www.netspi.com/blog/technical-blog/cloud-penetration-testing/anonymously-enumerating-azure-file-resources/>
- <https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/>
