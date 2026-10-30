# Fileless Multi-Stage Attack Chain — Forensic Analysis

**Type:** Malware forensic analysis (sanitized, educational) · **Severity:** Critical

> Generic reconstruction of a representative fileless attack chain from a set of
> malicious sample artifacts. Fully sanitized: no organization, no real host,
> URL, hash, or internal path. Indicators below are **representative placeholders**
> that illustrate the technique, not live indicators.

## Overview

Analysis of a set of malicious artifacts reconstructed a high-risk, multi-stage,
largely **fileless** intrusion chain: a weaponized Office document lures the user
into interaction, a script stager runs PowerShell to fetch and execute a payload
**in memory** from a trusted hosting platform, and living-off-the-land binaries
(LOLBins) stage a secondary executable while minimizing on-disk artifacts. A broad
internal target list indicates intent to move laterally.

## Kill chain & MITRE ATT&CK mapping

| Stage | Technique | ATT&CK |
|---|---|---|
| Delivery | Spearphishing attachment (Office lure: DOCX/PPTX) | T1566.001 |
| Execution | User interaction with an embedded OLE "Package" / lure button | T1204.002 |
| Execution | VBScript stager → PowerShell | T1059.005 / T1059.001 |
| Download | Ingress tool transfer from a trusted web platform | T1105 / T1102 |
| Defense evasion | In-memory execution (fileless), reduced on-disk footprint | T1027 |
| Defense evasion | Encoded blob decoded to a CAB via a signed system binary (LOLBin) | T1140 / T1218 |
| Defense evasion | Intermediate files deleted after execution | T1070.004 |
| Lateral movement | Admin SMB shares / UNC target list | T1021.002 |

## Chain reconstruction

1. **Lure.** An Office document embeds an OLE object and a visual "Click Here"
   element to induce the victim to execute embedded content.
2. **Stager.** User interaction invokes a VBScript stager, which launches
   PowerShell.
3. **In-memory payload.** PowerShell retrieves a remote script from a trusted
   public hosting platform and executes it **without writing it to disk**,
   defeating signature scanning of on-disk files.
4. **LOLBin staging.** A batch script writes a Base64 blob disguised as a
   certificate, uses a built-in signed utility to decode it into a CAB archive,
   expands the CAB into a secondary executable, runs it, then deletes the
   intermediates to minimize artifacts (living-off-the-land).
5. **Lateral movement intent.** A broad list of internal UNC/SMB targets
   indicates the operator planned rapid spread via administrative shares.

## Representative (sanitized) indicators

```
lure:           invoice-<redacted>.docx  (OLE Package + EMF "Click Here")
stager:         <redacted>.vbs  ->  powershell -nop -w hidden -enc <...>
download:       hxxps://<trusted-platform>/<redacted>/stager.ps1   (in-memory)
lolbin decode:  <signed-system-binary> -decode cert.tmp payload.cab
expand:         expand payload.cab -F:* .\dropped.exe
lateral:        \\<internal-host>\C$  (representative; list redacted)
```

## Detection opportunities

- **Office spawning script engines:** alert on `winword.exe`/`powerpnt.exe`
  spawning `wscript`/`cscript`/`powershell` (ASR rule).
- **PowerShell:** enable Script Block Logging + Module Logging; hunt `-enc`,
  hidden window, and remote download cradles.
- **LOLBins:** monitor the signed decode/expand utilities producing executables
  in user-writable paths.
- **Egress:** flag workstation fetches of raw scripts from public code-hosting.
- **SMB:** detect enumeration/writes to administrative shares (`C$`, `ADMIN$`).

## Remediation

- Deploy **Attack Surface Reduction** rules to block Office child processes and
  obfuscated-script execution.
- Enforce PowerShell **Constrained Language Mode** + full logging.
- Egress-filter / block raw downloads from public code-hosting on endpoints.
- Lock down administrative SMB shares; segment the network to limit lateral reach.
- User-awareness training on OLE / "enable content" lures.

## Takeaway

The chain's strength is **trust abuse + fileless execution**: a trusted document
format, a trusted hosting platform, and signed system binaries, leaving minimal
disk evidence. Defense depends on behavioral detection (process lineage, script
logging, egress) rather than file signatures.
