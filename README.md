# nimble-falcon-91 — a compact GitHub-compatible git forge

One Node 22 process, standard library only, serving four surfaces off a single
in-memory store:

- **Git smart HTTP** at `/{owner}/{repo}.git` — a hand-rolled object store
  (blobs, trees, commits, annotated tags; SHA-1 via `node:crypto`, zlib via
  `node:zlib`), packfile reader/writer with delta resolution, protocol v2
  (`ls-refs`, `fetch` with shallow/deepen) plus a v0 side-band-64k fallback,
  and v0 `receive-pack` with per-ref `report-status` (non-fast-forward updates
  are refused per ref while sibling refs still apply).
- **REST v3** under `/api/v3` — repositories, branches, commits, the contents
  API (create/update/delete with stale-sha 409), labels, issues and comments,
  and pull requests with three-way-mergeability, file diffs and squash merges.
- **GraphQL v4** at `/api/graphql` — a small self-contained parser/executor
  covering viewer/repository/issue/pull-request reads, introspection for the
  types `gh` probes, cursor-paginated connections, Relay `node(id:)` lookups,
  batched operations, and the create/close/merge/comment mutations.
- **MCP** at `/mcp` — JSON-RPC 2.0 streamable HTTP with `server/discover`
  (2026-07-28), the legacy `initialize` handshake, and six tools that act on
  the same store as REST.

The w7 variant is deliberately dense: helper-driven modules, a streaming
pkt-line codec that frames pack bytes straight into side-band chunks, and a
precomputed ancestor-closure index per commit so clone/fetch exclusion sets,
fast-forward checks and merge bases are set lookups instead of graph walks.

## Run

```sh
node main.ts
```

`main.ts` binds port 0, posts `{"port": N}` to `$MAKEFUN_ENV_URL/register`,
then polls `$MAKEFUN_ENV_URL/done` until the trial environment reports
`{"done": true}` and exits 0. Every surface expects
`Authorization: Bearer <$MAKEFUN_SHOP_TOKEN>`.

No dependencies, no build step: Node's type stripping runs the TypeScript
sources directly.
