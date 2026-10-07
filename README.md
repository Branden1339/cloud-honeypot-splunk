# Cloud Honeypot with Splunk SIEM

A cloud-hosted SSH honeypot (Cowrie) on AWS that logs real attacker activity, forwards it to a Splunk SIEM, and visualizes what the internet throws at an exposed server.

## Summary

I exposed a deliberately vulnerable SSH honeypot to the public internet for 17 days (Sep 19 to Oct 7, 2026) and analyzed the traffic in Splunk.

- 16,580 SSH connection attempts from 569 unique IPs
- One IP (189.15.188.39) generated about 90% of all connections, in two spikes on Sep 28 and 29
- 313 distinct IPs sent port-forwarding requests, all asking to reach the same mail server on port 25, consistent with probing for open proxies to relay spam
- Captured a malware dropper command (download, make executable, run) without any payload being saved or executed

## Architecture

Two AWS EC2 instances in us-east-2, each in its own security group:

| Instance | Role | Software |
|----------|------|----------|
| honeypot-cowrie | Exposed to the internet on port 2222 | Cowrie, Splunk Universal Forwarder |
| splunk-siem | Private, admin access from my IP only | Splunk Enterprise |

Cowrie writes every session to a JSON log. The Universal Forwarder watches that log and ships new events to Splunk over port 9997, restricted to the honeypot's private IP. Real admin SSH on the honeypot is restricted to my IP, so the exposed fake SSH service on 2222 is the only thing open to the world.

## Dashboard

![Dashboard overview](screenshots/dashboard-overview.png)

The Splunk dashboard has seven panels: connections per day, top attacker IPs, top countries, top credentials, top commands, a daily chart split by the top 3 IPs, and SMTP relay probes by country.

## Findings

### 1. One bot caused most of the volume

![Connection attempts per day](screenshots/panel-connections-per-day.png)

Daily traffic was low and steady until two spikes on Sep 28 and Sep 29. A single IP (189.15.188.39) accounts for 14,892 of 16,580 connections, about 90%. A second chart that splits each day by source IP shows the spikes are almost entirely that one address. Without that breakdown, the raw totals would suggest a large coordinated attack when it was really one noisy source.

### 2. The real diversity is in the unique IPs

![Top countries by unique IPs](screenshots/panel-top-countries.png)

569 distinct IPs touched the honeypot. Counting unique IPs per country gives a more honest picture than counting connections, where one bot would make a single country look dominant. The United States leads, but many US addresses are cloud-hosted servers, so this reflects where the address is registered and not who is behind it.

### 3. Attackers log in with default credentials

The most common username and password pairs were admin/admin, localadmin/localadmin, and root/root, followed by variations like Admin12345, password, changeme, and admin123. This is typical credential guessing against default and weak passwords. Cowrie accepts nearly every login by design, so a successful login means the honeypot let the bot in, not that anything was breached.

### 4. What attackers do after logging in

![Top commands run](screenshots/panel-top-commands.png)

After filtering out a connectivity probe that made up most of the raw commands, about 92% of the remaining commands were `uname`, which checks the operating system and architecture (MITRE T1082, System Information Discovery). Other commands checked whether `curl`, `wget`, `busybox`, or `python3` were installed, which tells the bot how it can download files.

One session attempted a download-and-execute chain: it fetched a file from a remote server with `curl`, fell back to `wget` if that failed, then tried to run it (MITRE T1105, Ingress Tool Transfer). The remote server was 192[.]3[.]92[.]87. Cowrie logged the command but saved no file, so there is no payload to analyze. I did not contact or scan that address.

### 5. A second behavior: SMTP relay probing

437 port-forwarding requests came from 313 distinct IPs, and every one asked for the same destination: 77[.]88[.]21[.]158 on port 25 (SMTP). Most senders made only a handful of requests and never ran commands. This is consistent with scanners testing for open proxies that could be used to relay spam (MITRE T1090, Proxy). The intent is inferred from the port, since Cowrie logs the request but does not carry it out.


## Limitations

- **Connections are not attacks.** Cowrie accepts almost every login by design (about 98% of connections), so "success" means the honeypot let the client in, not that anything was breached.
- **Event counts are not attack counts.** The logs hold about 130,000 events, but each connection produces roughly 8 events (connect, version, key exchange, login, commands, close). The 16,580 connections figure is the meaningful one.
- **Geolocation is approximate.** Country data shows where an IP address is registered, not where the person is. Many US addresses are cloud-hosted servers.
- **Intent is inferred.** Calling the port 25 traffic spam-relay probing is an interpretation based on the destination port, since Cowrie logs requests without carrying them out.
- **One bot skews the numbers.** A single IP made about 90% of connections, so raw totals overstate overall activity. This is why the dashboard also counts unique IPs.
- **Short observation window.** 17 days from one honeypot in one cloud region is a small sample and should not be generalized.
- **Early data issue.** An initial ingest double-counted events because a rotated log file was indexed twice. I fixed the Splunk input, cleaned the index, and re-ingested, so all figures here come from the corrected data.

## What I Learned

- Raw counts mislead. Splitting traffic by source IP and counting unique IPs changed the story from "heavy attack" to "one noisy bot over a steady background."
- Filtering matters. Most logged commands were a connectivity probe, and removing it exposed the real reconnaissance and dropper behavior.
- Log pipelines break in practical ways. I resolved JSON parsing problems with `props.conf`, a duplicate-ingest problem by cleaning the index, and a Splunk crash caused by running out of memory on a 1 GB instance (fixed by moving to a larger one).
- Safe handling of hostile data: I never contacted attacker infrastructure, and I defanged addresses so they cannot be clicked.

## How to Reproduce

1. Launch two Ubuntu EC2 instances (one for Cowrie, one for Splunk Enterprise) in the same VPC.
2. Install Cowrie on the honeypot under a dedicated non-root user and listen on port 2222. Keep real SSH on port 22 restricted to your own IP.
3. Open port 2222 to the internet on the honeypot's security group only.
4. Install Splunk Enterprise on the second instance. Allow port 9997 only from the honeypot's private IP, and port 8000 only from your own IP.
5. Install the Splunk Universal Forwarder on the honeypot and monitor the Cowrie JSON log directory.
6. Add a `props.conf` stanza for the `cowrie.json` sourcetype so each line is parsed as one JSON event.
7. Build searches on `eventid` values such as `cowrie.session.connect`, `cowrie.login.success`, `cowrie.command.input`, and `cowrie.direct-tcpip.request`.

- **Safe handling:** The honeypot held no real data, nothing captured was executed, and attacker infrastructure was never contacted.
