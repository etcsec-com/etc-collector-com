# Licensing

One license, one binary. Since v3.2.0 there is no Community/Pro split to
describe — every detection ships in the single published binary, under the
same license as everything else.

## The license

ETC Collector is licensed under the **Functional Source License, Version 1.1,
Apache 2.0 Future License (FSL-1.1-ALv2)**. The `LICENSE` file at the repo
root, `public/LICENSE`, and the `license.txt` embedded in the binary
(`etc-collector license`) all carry the same text, byte-identical to the
official reference: [fsl.software](https://fsl.software/).

## What it permits

- **Use, copy, modify, create derivative works, publicly perform, publicly
  display and redistribute** the software for any *Permitted Purpose*.
- A Permitted Purpose is **any purpose other than a Competing Use** — internal
  use, commercial use, production use, and use by or on behalf of a company
  are all explicitly permitted.
- A **patent grant**, on the same terms as the copyright license.

## What it restricts

A **Competing Use**: making the software available to others as part of a
commercial product or service that substitutes for it, substitutes for
another product/service we offer, or offers substantially similar
functionality. In plain terms: don't ship a competing AD/Entra security
auditor built on our source.

**If you're unsure whether your use is a Competing Use**, contact
`contact@etcsec.com` rather than guessing — see the standard text at
[fsl.software](https://fsl.software/) for the exact definition.

## The two-year conversion (Change Date)

Each release automatically becomes available under the plain **Apache
License 2.0** — no restrictions at all — on the second anniversary of that
release's publication date. Older versions become fully open source while
newer ones stay under FSL; this is a rolling window, not a one-time event.

## Licensing history

- Originally released under **Apache License 2.0** — fully open source, no
  restrictions.
- Later split: **Apache 2.0** for the openly-published detections, a
  proprietary **"ETC Collector License v1.0"** for the additional ones —
  an open-core model with two different licenses in play.
- **2026-08-26**: both sets of detections unified under the single
  **FSL-1.1-ALv2** license described above.
- **v3.2.0**: the detections themselves are unified too — one binary, one
  license, everything included. There is no longer a second, differently
  licensed set of detections to distinguish.

If you're unsure whether your intended use is a Competing Use under the
license, contact `contact@etcsec.com`.
