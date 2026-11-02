# Official vLEI schemas

Unmodified copies from [WebOfTrust/vLEI](https://github.com/WebOfTrust/vLEI/tree/main/schema/acdc) (`schema/acdc/`, Apache-2.0). `keri/common.py` loads them; keripy checks that each file matches its self-addressing `$id`, and `make keri-check` asserts the SAIDs below.

| credential | schema SAID |
|---|---|
| Qualified vLEI Issuer | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |
| Legal Entity | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` |
| Engagement Context Role | `EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw` |

The Agent Mandate Credential has no official schema yet (GLEIF discussion paper, p.45); `keri/common.py` holds this project's proposal.
