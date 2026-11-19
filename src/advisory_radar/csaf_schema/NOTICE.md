# Notice: the vendored CSAF schema files

These four files are copies of third-party JSON Schema documents. They are **unmodified, byte for byte**, and they
are the only copies advisory-radar reads. They are never fetched at run time: `advisory_radar.csaf` loads them from
this directory and resolves the CSAF schema's `$ref` links to the FIRST files from here, offline.
`tests/test_csaf.py` pins every file by its sha256 and checks that this notice names it.

Retrieved on 2026-11-19; each URL answered HTTP 200. The same digests were found on 2026-11-17.

| File | Source URL | What it is | sha256 |
| --- | --- | --- | --- |
| `csaf_json_schema.json` | https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json | The JSON schema of Common Security Advisory Framework Version 2.0, OASIS Standard of 18 November 2022 (JSON Schema draft 2020-12) | 29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262 |
| `cvss-v2.0.json` | https://www.first.org/cvss/cvss-v2.0.json | FIRST CVSS v2.0 JSON schema (JSON Schema draft-04), referenced by the CSAF schema | cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2 |
| `cvss-v3.0.json` | https://www.first.org/cvss/cvss-v3.0.json | FIRST CVSS v3.0 JSON schema (JSON Schema draft-04), referenced by the CSAF schema | b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919 |
| `cvss-v3.1.json` | https://www.first.org/cvss/cvss-v3.1.json | FIRST CVSS v3.1 JSON schema (JSON Schema draft-07), referenced by the CSAF schema | 77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f |

To move to another version, replace the files byte for byte, update the digests here, in `tests/test_csaf.py` and
in `docs/sources.md`, and re-run the tests: the pinned version and profile are part of the provider contract.

## OASIS (`csaf_json_schema.json`)

The schema is a normative part of the OASIS Standard "Common Security Advisory Framework Version 2.0", edited by
Langley Rock, Stefan Hagen and Thomas Schmidt (https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).
The specification's Notices section is reproduced here, as that section requires of every copy:

> Copyright © OASIS Open 2022. All Rights Reserved.
>
> All capitalized terms in the following text have the meanings assigned to them in the OASIS Intellectual Property
> Rights Policy (the "OASIS IPR Policy"). The full Policy may be found at the OASIS website.
>
> This document and translations of it may be copied and furnished to others, and derivative works that comment on
> or otherwise explain it or assist in its implementation may be prepared, copied, published, and distributed, in
> whole or in part, without restriction of any kind, provided that the above copyright notice and this section are
> included on all such copies and derivative works. However, this document itself may not be modified in any way,
> including by removing the copyright notice or references to OASIS, except as needed for the purpose of developing
> any document or deliverable produced by an OASIS Technical Committee (in which case the rules applicable to
> copyrights, as set forth in the OASIS IPR Policy, must be followed) or as required to translate it into languages
> other than English.
>
> The limited permissions granted above are perpetual and will not be revoked by OASIS or its successors or assigns.
>
> This document and the information contained herein is provided on an "AS IS" basis and OASIS DISCLAIMS ALL
> WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN
> WILL NOT INFRINGE ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR
> PURPOSE.

The name "OASIS" is a trademark of OASIS. It is used here only to refer to the organization and its official
output. The Technical Committee works in Non-Assertion Mode under the OASIS IPR Policy
(https://www.oasis-open.org/policies-guidelines/ipr).

## FIRST (`cvss-v2.0.json`, `cvss-v3.0.json`, `cvss-v3.1.json`)

Copyright (c) 2021, FIRST.ORG, INC. All rights reserved. Each file carries its own licence, the BSD 3-Clause
licence, in its `license` array. The files are unmodified, so each one retains its copyright notice, its conditions
and its disclaimer as the licence requires.
