# Pinned schema provenance

## `spec@1`

- Source repository: `orin-dx/agent-plugins`
- Source path: `shared/schemas/spec@1.json`
- Source revision: `b5e2db19cfd2358fe9dcecfce019eab936817e23`
- Schema identifier: `spec@1`
- SHA-256: `4bd715c2623a5ede39e787d3c90f972c5a9e760f84275705048ca54664aeaf3e`

`spec@1.json` is copied byte-for-byte from the recorded source revision. Any
schema update must be added as a new, versioned contract with its own provenance
record; it must not silently alter this file.

## Phase 2 workflow contracts

All four files below are copied byte-for-byte from `orin-dx/agent-plugins`,
`shared/schemas/`, at `b5e2db19cfd2358fe9dcecfce019eab936817e23`.

| Contract | SHA-256 |
| --- | --- |
| `requirement@1` | `48234475a9565231f3daaf533e8efb2eb138a452bf4cd96877e5304b3b587e0f` |
| `research-report@1` | `58fa7f58c4a3fa2ae9cf50f7ed6e89848f45a0e2cf421601593d9d13eaa85e24` |
| `plan@1` | `263220dbba382b5573f8a56f6bf0b170ee1019cd77946de6d7f6323166bd615e` |
| `arch-model@1` | `5014035957cc7e74f62ea99636d364691274badb7c8904c706b8e128227248e5` |

### `arch-model@2`

- Source repository: `orin-dx/agent-plugins`
- Source path: `shared/schemas/arch-model@2.json`
- Source revision: `6b49c245e6889b3971c7f7af77819913296c464a`
- Schema identifier: `arch-model@2`
- SHA-256: `9a2412cb088a2a43ac5caa35a853de59e163d939c579cf6929c00b3efa1c7da5`

`arch-model@2.json` is copied byte-for-byte from the recorded source revision. It is additive to `arch-model@1`; Wisp retains the version-one validator and does not migrate canonical model documents.

### `implementation-context@1`

- Source repository: `orin-dx/agent-plugins`
- Source path: `shared/schemas/implementation-context@1.json`
- Source revision: `f5ead0d8a6c7d5d986a84cc472536c5aed7913e9`
- Schema identifier: `implementation-context@1`
- SHA-256: `6918c30fedc871adc9bbf91ef115fbb35669939b606adff2abbf80da7e2cfd54`

The vendored bytes match the schema at the recorded source revision. Keep that revision available in the upstream history before merging or releasing a consumer that depends on it.
