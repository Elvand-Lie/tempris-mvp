# Tempris Collector v0.4.0 — Dependency Distribution Matrix

| Component | Approved Version | License / Authority | Bundling / Distribution | Required Handling | Decision |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tempris Collector** | 0.4.0 | Tempris Proprietary | Permitted | Release notices and SHA-256 manifest | Bundle |
| **Nuclei** | 3.8.0 | MIT (ProjectDiscovery) | Permitted | Include copyright notice and MIT license | Managed component (signed offline package / HTTPS update) |
| **Nuclei Templates** | v10.4.4 (commit `1e2578542e98818c5dfda8cb8f601023e7bcda69`) | MIT (ProjectDiscovery) | Permitted | Include copyright notice and MIT license; pin exact commit | Managed component (signed offline package / HTTPS update) |
| **Nmap + Npcap** | Operator-installed supported version | Nmap Public Source License (NPSL) / Npcap Commercial Terms | Prohibited | External operator prerequisite; operator installs separately | Never bundle, host, download, install, or update |

## Policy Rules

1. **Managed Component Boundary**: Only `"nuclei"` and `"nuclei_templates"` are valid managed components. Any manifest attempting to declare other components (including `"nmap"` or `"npcap"`) is rejected with `UnknownComponent`.
2. **Offline Package Safety**: Offline packages may contain only signed manifests and artifacts for approved managed components. Packages with extraneous files or unauthorized binaries are unconditionally rejected.
3. **External Dependencies**: Nmap and Npcap are discovered locally from approved directories and verified safely without shell invocation or automatic downloading.
