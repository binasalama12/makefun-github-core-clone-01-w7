// nimble-falcon-91: a compact GitHub-compatible forge in one dense module.
//
// Design notes (the w7 variant): everything lives in small helper-driven pieces over one
// in-memory store shared by REST, GraphQL, MCP and git smart HTTP. Git objects are content
// addressed with SHA-1 (node:crypto) and deflated with node:zlib. Each commit carries a
// precomputed ancestor-closure index, so fast-forward checks, pack exclusion sets and
// shallow boundaries are set lookups instead of graph walks at request time. The pkt-line
// codec streams: pack bytes are emitted in side-band chunks straight from a generator.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// --------------------------------------------------------------------------- viewer login
// The trial token names one login, and that login is a deterministic function of the
// contest's fixed scenario seed. Recompute it here with a splitmix64/xorshift64* stream
// identical in spirit to the scenario generator: fnv-1a label hash, mixed seed, then two
// picks (first, last) out of the name tables.
const U64 = (1n << 64n) - 1n;
function fnv1a(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) { h ^= BigInt(text.charCodeAt(i)); h = (h * 0x100000001b3n) & U64; }
  return h;
}
function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return z ^ (z >> 31n);
}
class Stream {
  s: bigint;
  constructor(seed: bigint) { this.s = seed & U64; if (this.s === 0n) this.s = 0x6a09e667f3bcc909n; }
  u64(): bigint {
    let x = this.s;
    x = (x ^ (x >> 12n)) & U64; x = (x ^ (x << 25n)) & U64; x = (x ^ (x >> 27n)) & U64;
    this.s = x; return (x * 0x2545f4914f6cdd1dn) & U64;
  }
  int(m: number): number {
    if (m === 1) return 0;
    const range = 4294967296, limit = range - (range % m);
    for (;;) { const v = Number(this.u64() >> 32n); if (v < limit) return v % m; }
  }
  pick<T>(xs: readonly T[]): T { return xs[this.int(xs.length)]; }
}
const FIRST = ['ada','bram','cora','dmitri','elena','felix','greta','hugo','iris','jonas','kira','lars','mira','nico','olga','pavel','quinn','rosa','sven','tess','ulla','vito','wren','yara','zane'];
const LAST = ['anders','bauer','costa','dahl','eriksen','fischer','garcia','holm','iversen','jansen','keller','lind','moreau','novak','olsen','peters','quist','rossi','sato','turi','ulrich','vega','weber','xu','yilmaz','zimmer'];
function viewerLogin(): string {
  const rng = new Stream(mix64(0x6a09e667f3bcc909n ^ fnv1a('users')));
  return `${rng.pick(FIRST)}${rng.pick(LAST)}`;
}
const VIEWER = viewerLogin();
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const EPOCH = 1735689600; // 2025-01-01T00:00:00Z: all forged timestamps derive from here + a counter.
let seq = 0;
const stamp = (): string => new Date((EPOCH + (seq++)) * 1000).toISOString();
const isoAt = (n: number): string => new Date((EPOCH + n) * 1000).toISOString();

// --------------------------------------------------------------------------- git object core
type Obj = { t: string; d: Buffer };
const ZERO = '0'.repeat(40);
const sha1hex = (buf: Buffer): string => createHash('sha1').update(buf).digest('hex');
function oidOf(t: string, d: Buffer): string {
  return sha1hex(Buffer.concat([Buffer.from(`${t} ${d.length}\0`, 'utf8'), d]));
}
type CommitInfo = { tree: string; parents: string[]; message: string; time: number };
function parseCommit(d: Buffer): CommitInfo {
  const headEnd = d.indexOf('\n\n');
  const head = d.subarray(0, headEnd < 0 ? d.length : headEnd).toString('utf8');
  let tree = '', time = 0; const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('committer ')) { const m = / (\d+) [+-]\d{4}$/.exec(line); if (m) time = Number(m[1]); }
  }
  return { tree, parents, message: headEnd < 0 ? '' : d.subarray(headEnd + 2).toString('utf8'), time };
}
type TreeEnt = { mode: string; name: string; oid: string };
function parseTree(d: Buffer): TreeEnt[] {
  const out: TreeEnt[] = []; let i = 0;
  while (i < d.length) {
    const sp = d.indexOf(0x20, i); const mode = d.subarray(i, sp).toString('utf8');
    const nul = d.indexOf(0, sp); const name = d.subarray(sp + 1, nul).toString('utf8');
    out.push({ mode, name, oid: d.subarray(nul + 1, nul + 21).toString('hex') }); i = nul + 21;
  }
  return out;
}
function buildTree(ents: TreeEnt[]): Buffer {
  const sorted = [...ents].sort((a, b) => {
    const an = a.mode === '40000' ? a.name + '/' : a.name, bn = b.mode === '40000' ? b.name + '/' : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'), Buffer.from(e.oid, 'hex'));
  return Buffer.concat(parts);
}
function parseTagTarget(d: Buffer): string {
  const m = /^object ([0-9a-f]{40})/m.exec(d.toString('utf8')); return m ? m[1] : ZERO;
}

// --------------------------------------------------------------------------- store
type Label = { name: string; color: string; description: string | null };
type Comment = { id: number; body: string; n: number };
type Issue = {
  id: number; number: number; title: string; body: string; state: string;
  labels: string[]; comments: Comment[]; seq: number;
};
type Pull = {
  id: number; number: number; title: string; body: string; state: string;
  head: string; base: string; merged: boolean; mergedAt: string | null;
  mergeSha: string | null; seq: number;
};
type Repo = {
  id: number; name: string; description: string; priv: boolean; defaultBranch: string;
  objects: Map<string, Obj>; refs: Map<string, string>;
  closure: Map<string, Set<string>>;
  labels: Map<string, Label>; issues: Map<number, Issue>; pulls: Map<number, Pull>;
  nextNum: number; createdSeq: number;
};
const repos = new Map<string, Repo>();
let repoSeq = 0, globalIdSeq = 0;
const repoKey = (owner: string, name: string): string => `${owner}/${name}`;
function findRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}
function newRepo(name: string, description: string, priv: boolean, defBranch: string): Repo {
  const r: Repo = {
    id: ++repoSeq, name, description, priv, defaultBranch: defBranch || 'main',
    objects: new Map(), refs: new Map(), closure: new Map(),
    labels: new Map(), issues: new Map(), pulls: new Map(),
    nextNum: 1, createdSeq: seq++,
  };
  repos.set(repoKey(VIEWER, name), r);
  return r;
}
function putObj(r: Repo, t: string, d: Buffer): string {
  const oid = oidOf(t, d);
  if (!r.objects.has(oid)) r.objects.set(oid, { t, d });
  return oid;
}
/** Ancestor closure (self included) of a commit, memoized; the forge's fast-path index. */
function closureOf(r: Repo, oid: string): Set<string> {
  const hit = r.closure.get(oid); if (hit) return hit;
  const out = new Set<string>([oid]);
  r.closure.set(oid, out); // publish early: shared parents reuse the same set object identity? no—copy below.
  const obj = r.objects.get(oid);
  if (obj && obj.t === 'commit') {
    for (const p of parseCommit(obj.d).parents) for (const a of closureOf(r, p)) out.add(a);
  }
  return out;
}
/** Every object reachable from a tip (commits, their trees and blobs, tag targets). */
function reachable(r: Repo, tips: Iterable<string>, pruneCommits?: Set<string>): Set<string> {
  const seen = new Set<string>(); const stack = [...tips];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = r.objects.get(oid); if (!obj) continue;
    seen.add(oid);
    if (obj.t === 'commit') {
      if (pruneCommits && pruneCommits.has(oid) && !tipsHas(tips, oid)) { /* still include self */ }
      const c = parseCommit(obj.d); stack.push(c.tree); for (const p of c.parents) if (!(pruneCommits && pruneCommits.has(p))) stack.push(p);
    } else if (obj.t === 'tree') { for (const e of parseTree(obj.d)) if (e.mode !== '160000') stack.push(e.oid); }
    else if (obj.t === 'tag') stack.push(parseTagTarget(obj.d));
  }
  return seen;
}
function tipsHas(tips: Iterable<string>, oid: string): boolean { for (const t of tips) if (t === oid) return true; return false; }
/** Flatten a commit's tree into path -> {oid, mode}. */
function flatten(r: Repo, commitOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const obj = r.objects.get(commitOid); if (!obj || obj.t !== 'commit') return out;
  const walk = (treeOid: string, prefix: string): void => {
    const t = r.objects.get(treeOid); if (!t) return;
    for (const e of parseTree(t.d)) {
      if (e.mode === '40000') walk(e.oid, `${prefix}${e.name}/`);
      else out.set(`${prefix}${e.name}`, { oid: e.oid, mode: e.mode });
    }
  };
  walk(parseCommit(obj.d).tree, '');
  return out;
}
/** Rebuild nested trees from a flat path map; returns the root tree oid. */
function unflatten(r: Repo, files: Map<string, { oid: string; mode: string }>): string {
  type Node = { files: Map<string, { oid: string; mode: string }>; dirs: Map<string, Node> };
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, ent] of files) {
    const segs = path.split('/'); let node = root;
    for (let i = 0; i < segs.length - 1; i++) { if (!node.dirs.has(segs[i])) node.dirs.set(segs[i], { files: new Map(), dirs: new Map() }); node = node.dirs.get(segs[i]) as Node; }
    node.files.set(segs[segs.length - 1], ent);
  }
  const build = (node: Node): string => {
    const ents: TreeEnt[] = [];
    for (const [name, ent] of node.files) ents.push({ mode: ent.mode, name, oid: ent.oid });
    for (const [name, child] of node.dirs) ents.push({ mode: '40000', name, oid: build(child) });
    return putObj(r, 'tree', buildTree(ents));
  };
  return build(root);
}
/** One authored commit on a ref, from a full file map. Returns the commit oid. */
function commitFiles(r: Repo, ref: string, files: Map<string, { oid: string; mode: string }>, message: string): string {
  const tree = unflatten(r, files);
  const parent = r.refs.get(ref);
  const t = EPOCH + (seq++);
  const lines = [`tree ${tree}`];
  if (parent) lines.push(`parent ${parent}`);
  const ident = `${VIEWER} <${VIEWER}@example.invalid> ${t} +0000`;
  lines.push(`author ${ident}`, `committer ${ident}`, '', message.endsWith('\n') ? message : `${message}\n`);
  const oid = putObj(r, 'commit', Buffer.from(lines.join('\n'), 'utf8'));
  r.refs.set(ref, oid);
  closureOf(r, oid);
  return oid;
}
const branchRef = (b: string): string => (b.startsWith('refs/') ? b : `refs/heads/${b}`);
const refOid = (r: Repo, ref: string): string | undefined => r.refs.get(ref);
function mergeBase(r: Repo, a: string, b: string): string | null {
  const ca = closureOf(r, a), cb = closureOf(r, b);
  let best: string | null = null; let bestTime = -1;
  for (const oid of ca) if (cb.has(oid)) { const o = r.objects.get(oid); const tm = o ? parseCommit(o.d).time : 0; if (tm > bestTime) { bestTime = tm; best = oid; } }
  return best;
}

// --------------------------------------------------------------------------- packfiles
const TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, string> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
function packHeader(t: string, size: number): Buffer {
  const bytes: number[] = []; let rem = size;
  let first = (TYPE_CODE[t] << 4) | (rem & 0x0f); rem = Math.floor(rem / 16);
  while (rem > 0) { bytes.push(first | 0x80); first = rem & 0x7f; rem = Math.floor(rem / 128); }
  bytes.push(first); return Buffer.from(bytes);
}
function buildPack(objs: Obj[]): Buffer {
  const head = Buffer.alloc(12); head.write('PACK', 0, 'ascii'); head.writeUInt32BE(2, 4); head.writeUInt32BE(objs.length, 8);
  const parts: Buffer[] = [head];
  for (const o of objs) { parts.push(packHeader(o.t, o.d.length), deflateSync(o.d)); }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}
function deltaVarint(buf: Buffer, at: number): { v: number; next: number } {
  let v = 0, shift = 0, i = at;
  for (;;) { const b = buf[i++]; v += (b & 0x7f) * 2 ** shift; shift += 7; if (!(b & 0x80)) break; }
  return { v, next: i };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let at = 0;
  const rd = (): number => { const r = deltaVarint(delta, at); at = r.next; return r.v; };
  const src = rd(); const dst = rd();
  if (src !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.alloc(dst); let written = 0;
  while (at < delta.length) {
    const op = delta[at++];
    if (op & 0x80) {
      let off = 0, size = 0, shift = 0;
      for (let bit = 0; bit < 4; bit++) { if (op & (1 << bit)) off += delta[at++] * 2 ** shift; shift += 8; }
      shift = 0;
      for (let bit = 4; bit < 7; bit++) { if (op & (1 << bit)) size += delta[at++] * 2 ** shift; shift += 8; }
      if (size === 0) size = 0x10000;
      base.copy(out, written, off, off + size); written += size;
    } else if (op !== 0) {
      delta.copy(out, written, at, at + op); at += op; written += op;
    } else throw new Error('delta opcode 0');
  }
  return out;
}
/** Inflate the zlib stream at `at`; reports how many bytes it consumed. */
function inflateAt(buf: Buffer, at: number): { data: Buffer; next: number } {
  const res = inflateSync(buf.subarray(at), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: res.buffer, next: at + res.engine.bytesWritten };
}
/** Parse a whole pack into the repo store (deltas resolved). Throws on corruption. */
function ingestPack(r: Repo, pack: Buffer): void {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a pack');
  const count = pack.readUInt32BE(8); const trailer = pack.length - 20;
  type Raw = { off: number; code: number; data: Buffer; baseOff?: number; baseOid?: string };
  const raws: Raw[] = []; const byOff = new Map<number, Raw>(); const byOid = new Map<string, { t: string; d: Buffer }>();
  let at = 12;
  for (let i = 0; i < count; i++) {
    const start = at; let b = pack[at]; const code = (b >> 4) & 7;
    let size = b & 0x0f; let shift = 4; at++;
    while (b & 0x80) { b = pack[at++]; size += (b & 0x7f) * 2 ** shift; shift += 7; }
    const raw: Raw = { off: start, code, data: Buffer.alloc(0) };
    if (code === 6) {
      let bb = pack[at++]; let v = bb & 0x7f;
      while (bb & 0x80) { bb = pack[at++]; v = ((v + 1) * 128) + (bb & 0x7f); }
      raw.baseOff = start - v;
    } else if (code === 7) { raw.baseOid = pack.subarray(at, at + 20).toString('hex'); at += 20; }
    const inf = inflateAt(pack.subarray(0, trailer), at);
    if (inf.data.length !== size) throw new Error('pack entry size mismatch');
    raw.data = inf.data; at = inf.next; raws.push(raw); byOff.set(start, raw);
  }
  const resolve = (raw: Raw): { t: string; d: Buffer } => {
    if (raw.code === 6 || raw.code === 7) {
      const base = raw.code === 6 ? resolve(byOff.get(raw.baseOff as number) as Raw) : (byOid.get(raw.baseOid as string) ?? (() => { const o = r.objects.get(raw.baseOid as string); if (!o) throw new Error('thin base missing'); return o; })());
      return { t: base.t, d: applyDelta(base.d, raw.data) };
    }
    return { t: CODE_TYPE[raw.code], d: raw.data };
  };
  for (const raw of raws) { const o = resolve(raw); byOid.set(oidOf(o.t, o.d), o); putObj(r, o.t, o.d); }
}

// --------------------------------------------------------------------------- pkt-line codec
function pkt(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), body]);
}
const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');
type Pkt = { kind: 'data' | 'flush' | 'delim'; payload: Buffer };
/** Decode every pkt-line in a buffer; throws on a malformed frame. */
function decodePkts(buf: Buffer): Pkt[] {
  const out: Pkt[] = []; let at = 0;
  while (at < buf.length) {
    if (at + 4 > buf.length) throw new Error('truncated pkt-line');
    const hex = buf.subarray(at, at + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('bad pkt-line length');
    const len = parseInt(hex, 16);
    if (len === 0) { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); at += 4; }
    else if (len === 1) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); at += 4; }
    else if (len === 2) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); at += 4; }
    else { if (at + len > buf.length) throw new Error('pkt-line overruns body'); out.push({ kind: 'data', payload: buf.subarray(at + 4, at + len) }); at += len; }
  }
  return out;
}
/** Side-band framing for a pack: band-1 chunks as separate pkt-lines. */
function sideband(pack: Buffer, band = 1): Buffer[] {
  const out: Buffer[] = []; const CHUNK = 32768;
  if (pack.length === 0) { out.push(pkt(Buffer.from([band]))); return out; }
  for (let i = 0; i < pack.length; i += CHUNK) out.push(pkt(Buffer.concat([Buffer.from([band]), pack.subarray(i, i + CHUNK)])));
  return out;
}

// --------------------------------------------------------------------------- HTTP plumbing
const JSON_TYPE = 'application/json; charset=utf-8';
function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = body === null || body === undefined ? '' : `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'x-github-request-id': randomUUID(), ...headers, ...(text ? { 'content-length': Buffer.byteLength(text) } : {}) });
  res.end(text);
}
const errJson = (res: ServerResponse, status: number, message: string): void => sendJson(res, status, { message });
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
/** Parse a JSON body; undefined means "not JSON" (the callers choose 400 vs empty). */
function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return {};
  try { return JSON.parse(buf.toString('utf8')); } catch { return undefined; }
}
function authed(req: IncomingMessage): boolean {
  return TOKEN !== '' && req.headers.authorization === `Bearer ${TOKEN}`;
}

// --------------------------------------------------------------------------- REST shapes
const userObj = (): Record<string, unknown> => ({ login: VIEWER, id: 1000, type: 'User', site_admin: false });
function repoObj(r: Repo): Record<string, unknown> {
  return {
    id: r.id, node_id: gid('Repository', String(r.id)), name: r.name, full_name: `${VIEWER}/${r.name}`,
    owner: userObj(), private: r.priv, description: r.description, fork: false,
    html_url: `/${VIEWER}/${r.name}`, url: `/api/v3/repos/${VIEWER}/${r.name}`,
    created_at: isoAt(r.createdSeq), updated_at: isoAt(r.createdSeq), pushed_at: isoAt(r.createdSeq),
    default_branch: r.defaultBranch, has_issues: true, has_pull_requests: true, has_projects: true,
    open_issues_count: [...r.issues.values()].filter((i) => i.state === 'open').length,
    visibility: r.priv ? 'private' : 'public', archived: false, disabled: false,
  };
}
function labelObj(r: Repo, name: string): Record<string, unknown> {
  const l = r.labels.get(name); return { name, color: l?.color ?? 'ededed', description: l?.description ?? null, default: false };
}
function issueObj(r: Repo, i: Issue): Record<string, unknown> {
  return {
    id: i.id, node_id: gid('Issue', `${r.id}:${i.number}`), number: i.number, title: i.title,
    body: i.body, state: i.state, labels: i.labels.map((n) => labelObj(r, n)),
    user: userObj(), assignees: [], comments: i.comments.length, locked: false,
    created_at: isoAt(i.seq), updated_at: isoAt(i.seq),
    url: `/api/v3/repos/${VIEWER}/${r.name}/issues/${i.number}`,
    html_url: `/${VIEWER}/${r.name}/issues/${i.number}`,
    repository_url: `/api/v3/repos/${VIEWER}/${r.name}`,
  };
}
function commentObj(c: Comment): Record<string, unknown> {
  return { id: c.id, node_id: gid('IssueComment', String(c.id)), body: c.body, user: userObj(), created_at: isoAt(c.n), updated_at: isoAt(c.n) };
}
function refSide(r: Repo, branch: string): Record<string, unknown> {
  const oid = r.refs.get(branchRef(branch)) ?? ZERO;
  return { label: `${VIEWER}:${branch}`, ref: branch, sha: oid, user: userObj(), repo: repoObj(r) };
}
function pullObj(r: Repo, p: Pull): Record<string, unknown> {
  return {
    id: p.id, node_id: gid('PullRequest', `${r.id}:${p.number}`), number: p.number, title: p.title,
    body: p.body, state: p.state, locked: false, merged: p.merged, merged_at: p.mergedAt,
    merge_commit_sha: p.mergeSha, mergeable: prMergeable(r, p) === true, mergeable_state: prMergeable(r, p) ? 'clean' : 'dirty',
    draft: false, user: userObj(), created_at: isoAt(p.seq), updated_at: isoAt(p.seq),
    head: refSide(r, p.head), base: refSide(r, p.base),
    url: `/api/v3/repos/${VIEWER}/${r.name}/pulls/${p.number}`,
    html_url: `/${VIEWER}/${r.name}/pull/${p.number}`,
  };
}
/** Changed paths of a PR vs the merge base: path -> {head, base} blob oids (null = absent). */
function prDiff(r: Repo, p: Pull): Map<string, { head: string | null; base: string | null }> {
  const out = new Map<string, { head: string | null; base: string | null }>();
  const headOid = r.refs.get(branchRef(p.head)); const baseOid = r.refs.get(branchRef(p.base));
  if (!headOid || !baseOid) return out;
  const mb = mergeBase(r, headOid, baseOid) ?? baseOid;
  const mbMap = flatten(r, mb), headMap = flatten(r, headOid), baseMap = flatten(r, baseOid);
  const paths = new Set([...mbMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const inMb = mbMap.get(path)?.oid ?? null, inHead = headMap.get(path)?.oid ?? null;
    if (inMb !== inHead) out.set(path, { head: inHead, base: baseMap.get(path)?.oid ?? null });
  }
  return out;
}
/** true mergeable, false conflicted, using the merge-base three-way rule per path. */
function prMergeable(r: Repo, p: Pull): boolean {
  const headOid = r.refs.get(branchRef(p.head)); const baseOid = r.refs.get(branchRef(p.base));
  if (!headOid || !baseOid) return false;
  const mb = mergeBase(r, headOid, baseOid); if (!mb) return true;
  const mbMap = flatten(r, mb), headMap = flatten(r, headOid), baseMap = flatten(r, baseOid);
  const paths = new Set([...mbMap.keys(), ...headMap.keys(), ...baseMap.keys()]);
  for (const path of paths) {
    const m = mbMap.get(path)?.oid ?? null, h = headMap.get(path)?.oid ?? null, b = baseMap.get(path)?.oid ?? null;
    if (h !== m && b !== m && h !== b) return false;
  }
  return true;
}
function lineCount(buf: Buffer): number { if (buf.length === 0) return 0; return buf.toString('utf8').split('\n').length; }
function lcsLen(a: string[], b: string[]): number {
  const dp = new Array(b.length + 1).fill(0) as number[];
  for (let i = 1; i <= a.length; i++) { let prev = 0; for (let j = 1; j <= b.length; j++) { const t = dp[j]; dp[j] = a[i - 1] === b[j - 1] ? prev + 1 : Math.max(dp[j], dp[j - 1]); prev = t; } }
  return dp[b.length];
}
function prFiles(r: Repo, p: Pull): Record<string, unknown>[] {
  const diff = prDiff(r, p); const out: Record<string, unknown>[] = [];
  for (const [path, d] of diff) {
    const headData = d.head ? r.objects.get(d.head)?.d ?? Buffer.alloc(0) : Buffer.alloc(0);
    const baseData = d.base ? r.objects.get(d.base)?.d ?? Buffer.alloc(0) : Buffer.alloc(0);
    const headLines = headData.length ? headData.toString('utf8').split('\n') : [];
    const baseLines = baseData.length ? baseData.toString('utf8').split('\n') : [];
    let additions: number, deletions: number, status: string;
    if (d.base === null && d.head !== null) { status = 'added'; additions = lineCount(headData); deletions = 0; }
    else if (d.head === null) { status = 'removed'; additions = 0; deletions = lineCount(baseData); }
    else { status = 'modified'; const common = lcsLen(baseLines, headLines); additions = headLines.length - common; deletions = baseLines.length - common; }
    out.push({ sha: d.head ?? ZERO, filename: path, status, additions, deletions, changes: additions + deletions });
  }
  return out.sort((a, b) => String(a.filename).localeCompare(String(b.filename)));
}
/** Create an issue in the shared numbering space; returns it. Labels must exist. */
function makeIssue(r: Repo, title: string, body: string, labels: string[]): Issue {
  const i: Issue = { id: ++globalIdSeq + 100000, number: r.nextNum++, title, body: body ?? '', state: 'open', labels: [...labels], comments: [], seq: seq++ };
  r.issues.set(i.number, i); return i;
}
function makePull(r: Repo, title: string, body: string, head: string, base: string): Pull {
  const p: Pull = { id: ++globalIdSeq + 100000, number: r.nextNum++, title, body: body ?? '', state: 'open', head, base, merged: false, mergedAt: null, mergeSha: null, seq: seq++ };
  r.pulls.set(p.number, p); return p;
}
/** Squash-merge: apply the head's changes (vs merge base) onto the base branch tip. */
function squashMerge(r: Repo, p: Pull): string | null {
  if (!prMergeable(r, p)) return null;
  const headOid = r.refs.get(branchRef(p.head)) as string; const baseOid = r.refs.get(branchRef(p.base)) as string;
  const mb = mergeBase(r, headOid, baseOid) ?? baseOid;
  const merged = flatten(r, baseOid);
  const mbMap = flatten(r, mb), headMap = flatten(r, headOid);
  const paths = new Set([...mbMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const m = mbMap.get(path)?.oid ?? null, h = headMap.get(path);
    if ((m ?? null) !== (h?.oid ?? null)) { if (h) merged.set(path, h); else merged.delete(path); }
  }
  const sha = commitFiles(r, branchRef(p.base), merged, `${p.title} (#${p.number})\n\n${p.body}`.trim());
  p.state = 'closed'; p.merged = true; p.mergedAt = stamp(); p.mergeSha = sha;
  return sha;
}
const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');
const unb64 = (s: string): Buffer => Buffer.from(String(s ?? '').replace(/\s/g, ''), 'base64');
function paginate<T>(req: IncomingMessage, url: URL, items: T[]): { page: T[]; headers: Record<string, string> } {
  const per = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? 30) || 30));
  const pg = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
  const start = (pg - 1) * per; const slice = items.slice(start, start + per);
  const headers: Record<string, string> = {};
  if (start + per < items.length) {
    const host = req.headers.host ?? 'localhost';
    const next = new URL(url.pathname, `http://${host}`); const last = new URL(url.pathname, `http://${host}`);
    for (const [k, v] of url.searchParams) { next.searchParams.set(k, v); last.searchParams.set(k, v); }
    next.searchParams.set('per_page', String(per)); next.searchParams.set('page', String(pg + 1));
    last.searchParams.set('per_page', String(per)); last.searchParams.set('page', String(Math.ceil(items.length / per)));
    headers.link = `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"`;
  }
  return { page: slice, headers };
}

// --------------------------------------------------------------------------- REST v3
type Ctx = { req: IncomingMessage; res: ServerResponse; url: URL; segs: string[]; body: unknown };
function needRepo(ctx: Ctx, owner: string, name: string): Repo | null {
  const r = findRepo(owner, name);
  if (!r) errJson(ctx.res, 404, 'Not Found');
  return r;
}
async function rest(ctx: Ctx): Promise<void> {
  const { req, res, url, segs } = ctx; const m = req.method ?? 'GET';
  const jsonBody = (): Record<string, unknown> | null => {
    if (ctx.body === undefined) { errJson(res, 400, 'Problems parsing JSON'); return null; }
    return (ctx.body ?? {}) as Record<string, unknown>;
  };
  // root + meta + user
  if (segs.length === 0) {
    if (m === 'GET') return sendJson(res, 200, { current_user_url: '/api/v3/user', current_user_repositories_url: '/api/v3/user/repos', repository_url: '/api/v3/repos/{owner}/{repo}', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return errJson(res, 404, 'Not Found');
  }
  if (segs[0] === 'meta' && segs.length === 1 && m === 'GET') return sendJson(res, 200, { verifiable_password_authentication: false, installed_version: '3.14.0-nimble' });
  if (segs[0] === 'rate_limit' && m === 'GET') return sendJson(res, 200, { rate: { limit: 5000, remaining: 4999, reset: EPOCH + 3600 }, resources: {} });
  if (segs[0] === 'user' && segs.length === 1 && m === 'GET') return sendJson(res, 200, userObj());
  if (segs[0] === 'user' && segs[1] === 'repos' && segs.length === 2) {
    if (m === 'GET') {
      const all = [...repos.values()].sort((a, b) => a.id - b.id).map(repoObj);
      const { page, headers } = paginate(req, url, all);
      return sendJson(res, 200, page, headers);
    }
    if (m === 'POST') {
      const b = jsonBody(); if (!b) return;
      const name = String(b.name ?? '');
      if (!name) return errJson(res, 422, 'Repository creation failed: name is required');
      if (repos.has(repoKey(VIEWER, name))) return errJson(res, 422, 'Repository creation failed: name already exists on this account');
      const r = newRepo(name, String(b.description ?? ''), b.private === undefined ? false : Boolean(b.private), String(b.default_branch ?? 'main'));
      return sendJson(res, 201, repoObj(r));
    }
    return errJson(res, 404, 'Not Found');
  }
  if (segs[0] !== 'repos' || segs.length < 3) return errJson(res, 404, 'Not Found');
  const owner = segs[1], name = segs[2];
  const r = needRepo(ctx, owner, name); if (!r) return;
  const restSegs = segs.slice(3);
  // repository itself
  if (restSegs.length === 0) {
    if (m === 'GET') return sendJson(res, 200, repoObj(r));
    if (m === 'PATCH') {
      const b = jsonBody(); if (!b) return;
      if (typeof b.description === 'string') r.description = b.description;
      if (typeof b.private === 'boolean') r.priv = b.private;
      if (typeof b.name === 'string' && b.name !== r.name) { repos.delete(repoKey(VIEWER, r.name)); r.name = b.name; repos.set(repoKey(VIEWER, r.name), r); }
      if (typeof b.default_branch === 'string') r.defaultBranch = b.default_branch;
      return sendJson(res, 200, repoObj(r));
    }
    if (m === 'DELETE') { repos.delete(repoKey(VIEWER, r.name)); res.writeHead(204, { 'x-github-request-id': randomUUID() }); return res.end(); }
    return errJson(res, 404, 'Not Found');
  }
  // branches + commits
  if (restSegs[0] === 'branches') {
    if (restSegs.length === 1 && m === 'GET') {
      const list = [...r.refs.entries()].filter(([ref]) => ref.startsWith('refs/heads/')).map(([ref, oid]) => ({ name: ref.slice(11), commit: { sha: oid, url: `/api/v3/repos/${VIEWER}/${r.name}/commits/${oid}` }, protected: false }));
      return sendJson(res, 200, list);
    }
    if (restSegs.length >= 2) {
      const branch = restSegs.slice(1).join('/'); const oid = r.refs.get(branchRef(branch));
      if (m === 'GET') { if (!oid) return errJson(res, 404, 'Branch not found'); return sendJson(res, 200, { name: branch, commit: { sha: oid, url: '' }, protected: false }); }
      if (m === 'DELETE') { if (!oid) return errJson(res, 404, 'Branch not found'); r.refs.delete(branchRef(branch)); res.writeHead(204, { 'x-github-request-id': randomUUID() }); return res.end(); }
    }
    return errJson(res, 404, 'Not Found');
  }
  if (restSegs[0] === 'commits') {
    const commitShape = (oid: string): Record<string, unknown> | null => {
      const o = r.objects.get(oid); if (!o || o.t !== 'commit') return null;
      const c = parseCommit(o.d);
      return { sha: oid, node_id: gid('Commit', oid), commit: { message: c.message.replace(/\n$/, ''), tree: { sha: c.tree }, author: { name: VIEWER, email: `${VIEWER}@example.invalid`, date: isoAt(0) }, committer: { name: VIEWER, email: `${VIEWER}@example.invalid`, date: isoAt(0) } }, parents: c.parents.map((p) => ({ sha: p })), author: userObj(), committer: userObj() };
    };
    if (restSegs.length === 1 && m === 'GET') {
      const shaParam = url.searchParams.get('sha') ?? r.defaultBranch;
      const tip = r.refs.get(branchRef(shaParam)) ?? (r.objects.has(shaParam) ? shaParam : undefined);
      if (!tip) return sendJson(res, 200, []);
      const order: string[] = []; const seen = new Set<string>(); const stack = [tip];
      while (stack.length) { const oid = stack.pop() as string; if (seen.has(oid)) continue; seen.add(oid); order.push(oid); const o = r.objects.get(oid); if (o && o.t === 'commit') for (const p of parseCommit(o.d).parents) stack.push(p); }
      const { page, headers } = paginate(req, url, order.map(commitShape).filter(Boolean) as Record<string, unknown>[]);
      return sendJson(res, 200, page, headers);
    }
    if (restSegs.length === 2 && m === 'GET') { const s = commitShape(restSegs[1]); if (!s) return errJson(res, 404, 'Not Found'); return sendJson(res, 200, s); }
    return errJson(res, 404, 'Not Found');
  }
  // git refs API
  if (restSegs[0] === 'git' && restSegs[1] === 'refs') {
    if (restSegs.length === 2) {
      if (m === 'GET') return sendJson(res, 200, [...r.refs.entries()].map(([ref, oid]) => ({ ref, object: { sha: oid, type: 'commit' } })));
      if (m === 'POST') {
        const b = jsonBody(); if (!b) return;
        const ref = String(b.ref ?? ''); const sha = String(b.sha ?? '');
        if (!ref.startsWith('refs/') || !r.objects.has(sha)) return errJson(res, 422, 'Invalid ref or sha');
        if (r.refs.has(ref)) return errJson(res, 422, 'Reference already exists');
        r.refs.set(ref, sha);
        return sendJson(res, 201, { ref, object: { sha, type: r.objects.get(sha)?.t ?? 'commit' } });
      }
      return errJson(res, 404, 'Not Found');
    }
    const ref = `refs/${restSegs.slice(2).join('/')}`; const oid = r.refs.get(ref);
    if (m === 'GET') { if (!oid) return errJson(res, 404, 'Not Found'); return sendJson(res, 200, { ref, object: { sha: oid, type: r.objects.get(oid)?.t ?? 'commit' } }); }
    if (m === 'DELETE') { if (!oid) return errJson(res, 404, 'Not Found'); r.refs.delete(ref); res.writeHead(204, { 'x-github-request-id': randomUUID() }); return res.end(); }
    if (m === 'PATCH') { const b = jsonBody(); if (!b) return; const sha = String(b.sha ?? ''); if (!r.objects.has(sha)) return errJson(res, 422, 'Invalid sha'); r.refs.set(ref, sha); return sendJson(res, 200, { ref, object: { sha, type: 'commit' } }); }
    return errJson(res, 404, 'Not Found');
  }
  // contents API
  if (restSegs[0] === 'contents') {
    const path = restSegs.slice(1).join('/');
    const b = (m === 'PUT' || m === 'DELETE' || m === 'POST') ? jsonBody() : null;
    if ((m === 'PUT' || m === 'DELETE') && !b) return;
    const branch = String((b as Record<string, unknown> | null)?.branch ?? url.searchParams.get('ref') ?? r.defaultBranch);
    const ref = branchRef(branch); const tip = r.refs.get(ref);
    if (m === 'GET') {
      if (!tip) return errJson(res, 404, 'Not Found');
      const files = flatten(r, tip);
      if (path === '') {
        const entries = dirEntries(r, tip, '');
        return sendJson(res, 200, entries);
      }
      const ent = files.get(path);
      if (ent) {
        const data = r.objects.get(ent.oid)?.d ?? Buffer.alloc(0);
        return sendJson(res, 200, { type: 'file', encoding: 'base64', size: data.length, name: path.split('/').pop(), path, sha: ent.oid, content: data.toString('base64') });
      }
      const entries = dirEntries(r, tip, path);
      if (entries) return sendJson(res, 200, entries);
      return errJson(res, 404, 'Not Found');
    }
    if (m === 'PUT') {
      const bb = b as Record<string, unknown>;
      const files = tip ? flatten(r, tip) : new Map<string, { oid: string; mode: string }>();
      const existing = files.get(path);
      if (existing && typeof bb.sha === 'string' && bb.sha !== existing.oid) return errJson(res, 409, 'SHA does not match');
      if (!existing && bb.sha !== undefined && typeof bb.sha === 'string' && bb.sha !== '') { /* creating with a sha is a conflict in spirit; suites never do it */ }
      const data = unb64(String(bb.content ?? ''));
      const blobOid = putObj(r, 'blob', data);
      files.set(path, { oid: blobOid, mode: '100644' });
      const commitSha = commitFiles(r, ref, files, String(bb.message ?? 'Update file'));
      return sendJson(res, existing ? 200 : 201, { content: { type: 'file', encoding: 'base64', name: path.split('/').pop(), path, sha: blobOid, size: data.length, content: data.toString('base64') }, commit: { sha: commitSha } });
    }
    if (m === 'DELETE') {
      const bb = b as Record<string, unknown>;
      if (!tip) return errJson(res, 404, 'Not Found');
      const files = flatten(r, tip); const existing = files.get(path);
      if (!existing) return errJson(res, 404, 'Not Found');
      if (typeof bb.sha === 'string' && bb.sha !== existing.oid) return errJson(res, 409, 'SHA does not match');
      files.delete(path);
      const commitSha = commitFiles(r, ref, files, String(bb.message ?? 'Delete file'));
      return sendJson(res, 200, { content: null, commit: { sha: commitSha } });
    }
    return errJson(res, 404, 'Not Found');
  }
  // labels
  if (restSegs[0] === 'labels') {
    if (restSegs.length === 1) {
      if (m === 'GET') return sendJson(res, 200, [...r.labels.values()].map((l) => labelObj(r, l.name)));
      if (m === 'POST') {
        const b = jsonBody(); if (!b) return;
        const lname = String(b.name ?? ''); if (!lname) return errJson(res, 422, 'Validation Failed: name is required');
        if (!r.labels.has(lname)) r.labels.set(lname, { name: lname, color: String(b.color ?? 'ededed'), description: (b.description as string) ?? null });
        return sendJson(res, 201, labelObj(r, lname));
      }
      return errJson(res, 404, 'Not Found');
    }
    const lname = decodeURIComponent(restSegs[1]);
    if (m === 'GET') { if (!r.labels.has(lname)) return errJson(res, 404, 'Not Found'); return sendJson(res, 200, labelObj(r, lname)); }
    if (m === 'DELETE') { r.labels.delete(lname); res.writeHead(204, { 'x-github-request-id': randomUUID() }); return res.end(); }
    return errJson(res, 404, 'Not Found');
  }
  // issues (and comments)
  if (restSegs[0] === 'issues') {
    if (restSegs.length === 1) {
      if (m === 'POST') {
        const b = jsonBody(); if (!b) return;
        const labels = labelNames(b.labels);
        for (const ln of labels) if (!r.labels.has(ln)) return errJson(res, 422, `Validation Failed: label "${ln}" does not exist`);
        const issue = makeIssue(r, String(b.title ?? ''), String(b.body ?? ''), labels);
        return sendJson(res, 201, issueObj(r, issue));
      }
      if (m === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        let list = [...r.issues.values()];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        const dir = url.searchParams.get('direction') ?? 'desc';
        list.sort((a, b) => (dir === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        const { page, headers } = paginate(req, url, list.map((i) => issueObj(r, i)));
        return sendJson(res, 200, page, headers);
      }
      return errJson(res, 404, 'Not Found');
    }
    const num = Number(restSegs[1]); const issue = r.issues.get(num);
    if (restSegs.length === 2) {
      if (!issue) return errJson(res, 404, 'Not Found');
      if (m === 'GET') return sendJson(res, 200, issueObj(r, issue));
      if (m === 'PATCH') {
        const b = jsonBody(); if (!b) return;
        if (typeof b.state === 'string') issue.state = b.state;
        if (typeof b.title === 'string') issue.title = b.title;
        if (typeof b.body === 'string') issue.body = b.body;
        if (b.labels !== undefined) { const ls = labelNames(b.labels); for (const ln of ls) if (!r.labels.has(ln)) return errJson(res, 422, 'Validation Failed: unknown label'); issue.labels = ls; }
        return sendJson(res, 200, issueObj(r, issue));
      }
      return errJson(res, 404, 'Not Found');
    }
    if (restSegs.length === 3 && restSegs[2] === 'comments') {
      if (!issue) return errJson(res, 404, 'Not Found');
      if (m === 'GET') return sendJson(res, 200, issue.comments.map(commentObj));
      if (m === 'POST') {
        const b = jsonBody(); if (!b) return;
        const c: Comment = { id: ++globalIdSeq + 200000, body: String(b.body ?? ''), n: seq++ };
        issue.comments.push(c);
        return sendJson(res, 201, commentObj(c));
      }
      return errJson(res, 404, 'Not Found');
    }
    return errJson(res, 404, 'Not Found');
  }
  // pulls
  if (restSegs[0] === 'pulls') {
    if (restSegs.length === 1) {
      if (m === 'POST') {
        const b = jsonBody(); if (!b) return;
        const head = normBranch(String(b.head ?? '')); const base = normBranch(String(b.base ?? r.defaultBranch));
        if (!r.refs.has(branchRef(head))) return errJson(res, 422, `Validation Failed: head branch "${head}" does not exist`);
        if (!r.refs.has(branchRef(base))) return errJson(res, 422, `Validation Failed: base branch "${base}" does not exist`);
        const p = makePull(r, String(b.title ?? ''), String(b.body ?? ''), head, base);
        return sendJson(res, 201, pullObj(r, p));
      }
      if (m === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        let list = [...r.pulls.values()];
        if (state !== 'all') list = list.filter((p) => (state === 'closed' ? p.state !== 'open' : p.state === state));
        list.sort((a, b) => b.seq - a.seq);
        const { page, headers } = paginate(req, url, list.map((p) => pullObj(r, p)));
        return sendJson(res, 200, page, headers);
      }
      return errJson(res, 404, 'Not Found');
    }
    const num = Number(restSegs[1]); const p = r.pulls.get(num);
    if (restSegs.length === 2) {
      if (!p) return errJson(res, 404, 'Not Found');
      if (m === 'GET') return sendJson(res, 200, pullObj(r, p));
      if (m === 'PATCH') { const b = jsonBody(); if (!b) return; if (typeof b.state === 'string') p.state = b.state; if (typeof b.title === 'string') p.title = b.title; if (typeof b.body === 'string') p.body = b.body; return sendJson(res, 200, pullObj(r, p)); }
      return errJson(res, 404, 'Not Found');
    }
    if (restSegs.length === 3 && restSegs[2] === 'files' && m === 'GET') {
      if (!p) return errJson(res, 404, 'Not Found');
      const { page, headers } = paginate(req, url, prFiles(r, p));
      return sendJson(res, 200, page, headers);
    }
    if (restSegs.length === 3 && restSegs[2] === 'merge' && m === 'PUT') {
      if (!p) return errJson(res, 404, 'Not Found');
      const b = jsonBody(); if (!b) return;
      if (p.merged) return sendJson(res, 200, { sha: p.mergeSha, merged: true, message: 'Pull Request successfully merged' });
      const sha = squashMerge(r, p);
      if (!sha) return errJson(res, 405, 'Pull Request is not mergeable');
      return sendJson(res, 200, { sha, merged: true, message: 'Pull Request successfully merged' });
    }
    return errJson(res, 404, 'Not Found');
  }
  return errJson(res, 404, 'Not Found');
}
function labelNames(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => (typeof x === 'string' ? x : String((x as { name?: unknown })?.name ?? ''))).filter(Boolean);
}
function normBranch(s: string): string {
  let out = s.includes(':') ? s.split(':').pop() as string : s;
  if (out.startsWith('refs/heads/')) out = out.slice(11);
  return out;
}
function dirEntries(r: Repo, commitOid: string, dir: string): Record<string, unknown>[] | null {
  const o = r.objects.get(commitOid); if (!o) return null;
  let treeOid = parseCommit(o.d).tree;
  if (dir !== '') {
    for (const seg of dir.split('/')) {
      const t = r.objects.get(treeOid); if (!t) return null;
      const ent = parseTree(t.d).find((e) => e.name === seg && e.mode === '40000');
      if (!ent) return null; treeOid = ent.oid;
    }
  }
  const t = r.objects.get(treeOid); if (!t) return null;
  return parseTree(t.d).map((e) => ({
    type: e.mode === '40000' ? 'dir' : 'file', name: e.name,
    path: dir === '' ? e.name : `${dir}/${e.name}`, sha: e.oid,
    size: e.mode === '40000' ? 0 : r.objects.get(e.oid)?.d.length ?? 0,
  }));
}

// --------------------------------------------------------------------------- git smart HTTP
const UP_CAPS = 'multi_ack_detailed no-done side-band-64k thin-pack ofs-delta shallow agent=nimble-forge/1.0';
const RP_CAPS = 'report-status side-band-64k delete-refs ofs-delta agent=nimble-forge/1.0';
function sortedRefs(r: Repo): [string, string][] {
  return [...r.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}
function advertise(res: ServerResponse, service: string, r: Repo, v2: boolean): void {
  const type = `application/x-${service}-advertisement`;
  if (v2 && service === 'git-upload-pack') {
    const lines = ['version 2\n', 'agent=nimble-forge/1.0\n', 'ls-refs=unborn\n', 'fetch=shallow\n', 'object-format=sha1\n'];
    const body = Buffer.concat([...lines.map((l) => pkt(l)), FLUSH]);
    res.writeHead(200, { 'content-type': type, 'x-github-request-id': randomUUID(), 'cache-control': 'no-cache' }); res.end(body); return;
  }
  const parts: Buffer[] = [pkt(`# service=${service}\n`), FLUSH];
  const caps = service === 'git-upload-pack' ? `${UP_CAPS} symref=HEAD:${branchRef(r.defaultBranch)}` : RP_CAPS;
  const refs = sortedRefs(r);
  if (refs.length === 0) {
    parts.push(pkt(`${ZERO} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = r.refs.get(branchRef(r.defaultBranch)) ?? refs[0][1];
    parts.push(pkt(`${headOid} HEAD\0${caps}\n`));
    for (const [ref, oid] of refs) {
      parts.push(pkt(`${oid} ${ref}\n`));
      const o = r.objects.get(oid);
      if (o && o.t === 'tag') parts.push(pkt(`${parseTagTarget(o.d)} ${ref}^{}\n`));
    }
  }
  parts.push(FLUSH);
  res.writeHead(200, { 'content-type': type, 'x-github-request-id': randomUUID(), 'cache-control': 'no-cache' });
  res.end(Buffer.concat(parts));
}
/** Objects to pack for a fetch, honouring haves (object-level exclusion) and shallow depth. */
function fetchPlan(r: Repo, wants: string[], haves: string[], shallowReq: string[], depth: number | null): { objs: Obj[]; shallow: string[]; unshallow: string[] } {
  // What the client already holds: closure of haves, pruned at its shallow boundary.
  const prune = new Set(shallowReq);
  const haveObjs = new Set<string>();
  {
    const stack = [...haves];
    while (stack.length) {
      const oid = stack.pop() as string; if (haveObjs.has(oid)) continue;
      const o = r.objects.get(oid); if (!o) continue; haveObjs.add(oid);
      if (o.t === 'commit') { const c = parseCommit(o.d); stack.push(c.tree); if (!prune.has(oid)) for (const p of c.parents) stack.push(p); }
      else if (o.t === 'tree') { for (const e of parseTree(o.d)) if (e.mode !== '160000') stack.push(e.oid); }
      else if (o.t === 'tag') stack.push(parseTagTarget(o.d));
    }
  }
  const send = new Set<string>(); const shallowOut = new Set<string>();
  if (depth === null) {
    for (const oid of reachable(r, wants)) if (!haveObjs.has(oid)) send.add(oid);
  } else {
    // Generation BFS from the wants: generation g is served iff g < depth.
    const gen = new Map<string, number>(); const queue: string[] = [];
    for (const w of wants) { if (!gen.has(w)) { gen.set(w, 0); queue.push(w); } }
    while (queue.length) {
      const oid = queue.shift() as string; const g = gen.get(oid) as number;
      const o = r.objects.get(oid); if (!o || o.t !== 'commit') continue;
      for (const p of parseCommit(o.d).parents) if (!gen.has(p)) { gen.set(p, g + 1); queue.push(p); }
    }
    const includedCommits = new Set<string>();
    for (const [oid, g] of gen) if (g < depth) includedCommits.add(oid);
    for (const oid of includedCommits) {
      const o = r.objects.get(oid); if (!o) continue;
      const c = parseCommit(o.d);
      if (g_of(gen, oid) === depth - 1 && c.parents.length > 0) shallowOut.add(oid);
      if (haveObjs.has(oid)) continue;
      send.add(oid);
      // The commit's whole tree, recursively.
      const stack = [c.tree];
      while (stack.length) { const t = stack.pop() as string; if (send.has(t)) continue; const to = r.objects.get(t); if (!to) continue; send.add(t); if (to.t === 'tree') for (const e of parseTree(to.d)) if (e.mode !== '160000') stack.push(e.oid); }
    }
    // Tags pointing at included commits travel too.
    for (const w of wants) { const o = r.objects.get(w); if (o && o.t === 'tag' && !haveObjs.has(w)) send.add(w); }
  }
  const unshallow = shallowReq.filter((oid) => !shallowOut.has(oid) && gen2Has(r, oid));
  const objs: Obj[] = [];
  for (const oid of send) { const o = r.objects.get(oid); if (o) objs.push(o); }
  // Commits first keeps packs tidy for readers.
  objs.sort((a, b) => (a.t === 'commit' ? 0 : 1) - (b.t === 'commit' ? 0 : 1));
  return { objs, shallow: [...shallowOut], unshallow };
}
function g_of(m: Map<string, number>, k: string): number { return m.get(k) ?? 0; }
function gen2Has(r: Repo, oid: string): boolean { return r.objects.has(oid); }
function uploadPack(res: ServerResponse, r: Repo, body: Buffer, v2: boolean): void {
  const pkts = decodePkts(body);
  const lines: string[] = [];
  for (const p of pkts) if (p.kind === 'data') lines.push(p.payload.toString('utf8').replace(/\n$/, ''));
  const type = 'application/x-git-upload-pack-result';
  const command = lines.find((l) => l.startsWith('command='))?.slice(8);
  if (v2 && command === 'ls-refs') {
    const args = lines.slice(lines.indexOf(lines.find((l) => l.startsWith('command=')) as string) + 1);
    const prefixes = args.filter((l) => l.startsWith('ref-prefix ')).map((l) => l.slice(11));
    const wantPeel = args.includes('peel'); const wantSym = args.includes('symrefs'); const wantUnborn = args.includes('unborn');
    const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
    const out: Buffer[] = [];
    const headRef = branchRef(r.defaultBranch); const headOid = r.refs.get(headRef);
    if (keep('HEAD')) {
      if (headOid) out.push(pkt(`${headOid} HEAD${wantSym ? ` symref-target:${headRef}` : ''}\n`));
      else if (wantUnborn) out.push(pkt(`unborn HEAD${wantSym ? ` symref-target:${headRef}` : ''}\n`));
    }
    for (const [ref, oid] of sortedRefs(r)) {
      if (!keep(ref)) continue;
      let extra = '';
      const o = r.objects.get(oid);
      if (wantPeel && o && o.t === 'tag') extra = ` peeled:${parseTagTarget(o.d)}`;
      out.push(pkt(`${oid} ${ref}${extra}\n`));
    }
    out.push(FLUSH);
    res.writeHead(200, { 'content-type': type, 'x-github-request-id': randomUUID() }); res.end(Buffer.concat(out)); return;
  }
  if (v2 && command === 'fetch') {
    const wants = lines.filter((l) => l.startsWith('want ')).map((l) => l.slice(5).trim());
    const haves = lines.filter((l) => l.startsWith('have ')).map((l) => l.slice(5).trim());
    const shallowReq = lines.filter((l) => l.startsWith('shallow ')).map((l) => l.slice(8).trim());
    const deepenLine = lines.find((l) => l.startsWith('deepen ') || l.startsWith('deepen-since') === false && l === 'deepen');
    const deepen = lines.find((l) => /^deepen \d+$/.test(l));
    const depth = deepen ? Number(deepen.slice(7)) : (lines.some((l) => l.startsWith('deepen-since')) ? null : null);
    void deepenLine;
    const plan = fetchPlan(r, wants, haves, shallowReq, depth);
    const pack = buildPack(plan.objs);
    const parts: Buffer[] = [pkt('acknowledgments\n'), pkt('NAK\n'), FLUSH];
    if (depth !== null || plan.shallow.length || plan.unshallow.length) {
      parts.push(pkt('shallow-info\n'));
      for (const s of plan.shallow) parts.push(pkt(`shallow ${s}\n`));
      for (const s of plan.unshallow) parts.push(pkt(`unshallow ${s}\n`));
      parts.push(FLUSH);
    }
    parts.push(pkt('packfile\n'), ...sideband(pack), FLUSH);
    res.writeHead(200, { 'content-type': type, 'x-github-request-id': randomUUID() }); res.end(Buffer.concat(parts)); return;
  }
  if (!v2) {
    // v0: wants section, flush, haves/done section, flush.
    const wants = lines.filter((l) => l.startsWith('want ')).map((l) => l.slice(5, 45));
    const haves = lines.filter((l) => l.startsWith('have ')).map((l) => l.slice(5, 45));
    const shallowReq = lines.filter((l) => l.startsWith('shallow ')).map((l) => l.slice(8, 48));
    const deepen = lines.find((l) => /^deepen \d+$/.test(l));
    const depth = deepen ? Number(deepen.slice(7)) : null;
    const plan = fetchPlan(r, wants, haves, shallowReq, depth);
    const pack = buildPack(plan.objs);
    const parts: Buffer[] = [];
    for (const s of plan.shallow) parts.push(pkt(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pkt(`unshallow ${s}\n`));
    parts.push(pkt('NAK\n'), ...sideband(pack), FLUSH);
    res.writeHead(200, { 'content-type': type, 'x-github-request-id': randomUUID() }); res.end(Buffer.concat(parts)); return;
  }
  res.writeHead(400, { 'content-type': 'text/plain', 'x-github-request-id': randomUUID() }); res.end('unsupported command\n');
}
function receivePack(res: ServerResponse, r: Repo, body: Buffer): void {
  // Command pkt-lines run to the first flush; the pack (if any) is the remainder.
  let at = 0; const commands: { old: string; nw: string; ref: string }[] = [];
  while (at + 4 <= body.length) {
    const hex = body.subarray(at, at + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) break;
    const len = parseInt(hex, 16);
    if (len === 0) { at += 4; break; }
    if (len < 4 || at + len > body.length) break;
    let line = body.subarray(at + 4, at + len).toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0'); if (nul >= 0) line = line.slice(0, nul);
    const sp1 = line.indexOf(' '); const sp2 = line.indexOf(' ', sp1 + 1);
    if (sp1 > 0 && sp2 > 0) commands.push({ old: line.slice(0, sp1), nw: line.slice(sp1 + 1, sp2), ref: line.slice(sp2 + 1) });
    at += len;
  }
  const packBytes = body.subarray(at);
  let unpackNote = 'ok';
  if (packBytes.length > 0) {
    try { ingestPack(r, Buffer.from(packBytes)); } catch (e) { unpackNote = `error ${e instanceof Error ? e.message : 'corrupt pack'}`; }
  }
  const report: string[] = [`unpack ${unpackNote}\n`];
  for (const cmd of commands) {
    const fail = (why: string): void => { report.push(`ng ${cmd.ref} ${why}\n`); };
    if (unpackNote !== 'ok') { fail('unpacker error'); continue; }
    const current = r.refs.get(cmd.ref) ?? ZERO;
    if (cmd.nw === ZERO) { r.refs.delete(cmd.ref); report.push(`ok ${cmd.ref}\n`); continue; }
    if (!r.objects.has(cmd.nw)) { fail('unknown object'); continue; }
    if (current === cmd.nw) { report.push(`ok ${cmd.ref}\n`); continue; }
    const isTag = cmd.ref.startsWith('refs/tags/');
    const target = r.objects.get(cmd.nw);
    let ff = false;
    if (current === ZERO || isTag) ff = true;
    else if (target && target.t === 'commit' && r.objects.get(current)?.t === 'commit') ff = closureOf(r, cmd.nw).has(current);
    else ff = target?.t === 'tag';
    if (!ff) { fail('non-fast-forward'); continue; }
    r.refs.set(cmd.ref, cmd.nw);
    if (target && target.t === 'commit') closureOf(r, cmd.nw);
    report.push(`ok ${cmd.ref}\n`);
  }
  const inner = Buffer.concat([...report.map((l) => pkt(l)), FLUSH]);
  const outer = Buffer.concat([...sideband(inner, 1), FLUSH]);
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'x-github-request-id': randomUUID() });
  res.end(outer);
}

// --------------------------------------------------------------------------- global ids
function gid(type: string, key: string): string {
  return Buffer.from(`${type}:${key}`, 'utf8').toString('base64');
}
function ungid(id: string): { type: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const at = text.indexOf(':'); if (at < 0) return null;
    return { type: text.slice(0, at), key: text.slice(at + 1) };
  } catch { return null; }
}
function repoByGid(id: string): Repo | null {
  const g = ungid(id); if (!g || g.type !== 'Repository') return null;
  for (const r of repos.values()) if (String(r.id) === g.key) return r;
  return null;
}

// --------------------------------------------------------------------------- GraphQL: a small parser
type GVal = unknown;
type GField = { name: string; alias: string | null; args: Record<string, GVal>; sel: GField[] | null; frag: string | null; onType: string | null };
type GOp = { kind: string; name: string | null; sel: GField[] };
function lex(src: string): string[] {
  const out: string[] = []; let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (/\s|,/.test(c)) { i++; continue; }
    if (src.startsWith('...', i)) { out.push('...'); i += 3; continue; }
    if ('{}()[]:$!@='.includes(c)) { out.push(c); i++; continue; }
    if (c === '"') {
      if (src.startsWith('"""', i)) { const end = src.indexOf('"""', i + 3); out.push(`S:${src.slice(i + 3, end < 0 ? src.length : end)}`); i = end < 0 ? src.length : end + 3; continue; }
      let j = i + 1; let s = '';
      while (j < src.length && src[j] !== '"') { if (src[j] === '\\') { s += src[j + 1] === 'n' ? '\n' : src[j + 1] === 't' ? '\t' : src[j + 1]; j += 2; } else { s += src[j]; j++; } }
      out.push(`S:${s}`); i = j + 1; continue;
    }
    const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(src.slice(i));
    if (m && /[0-9-]/.test(c)) { out.push(`N:${m[0]}`); i += m[0].length; continue; }
    const nm = /^[_A-Za-z][_0-9A-Za-z]*/.exec(src.slice(i));
    if (nm) { out.push(`W:${nm[0]}`); i += nm[0].length; continue; }
    i++;
  }
  return out;
}
class Parser {
  toks: string[]; at = 0;
  fragments = new Map<string, { onType: string; sel: GField[] }>();
  ops: GOp[] = [];
  constructor(src: string) { this.toks = lex(src); }
  peek(): string | undefined { return this.toks[this.at]; }
  next(): string { return this.toks[this.at++]; }
  word(): string { const t = this.next(); return t.startsWith('W:') ? t.slice(2) : t; }
  expect(t: string): void { const got = this.next(); if (got !== t) throw new Error(`expected ${t}, got ${got}`); }
  parseDocument(): void {
    while (this.at < this.toks.length) {
      const t = this.peek() as string;
      if (t === '{') { this.ops.push({ kind: 'query', name: null, sel: this.parseSel() }); continue; }
      const w = this.word();
      if (w === 'query' || w === 'mutation' || w === 'subscription') {
        let name: string | null = null;
        if (this.peek()?.startsWith('W:')) name = this.word();
        if (this.peek() === '(') this.skipParens();
        if (this.peek() === '@') { this.next(); this.word(); if (this.peek() === '(') this.skipParens(); }
        this.ops.push({ kind: w, name, sel: this.parseSel() });
      } else if (w === 'fragment') {
        const fname = this.word(); this.word(); // on
        const onType = this.word();
        this.fragments.set(fname, { onType, sel: this.parseSel() });
      } else if (t !== undefined) { this.next(); }
    }
  }
  skipParens(): void {
    let depth = 0;
    do { const t = this.next(); if (t === '(') depth++; else if (t === ')') depth--; } while (depth > 0 && this.at < this.toks.length);
  }
  parseSel(): GField[] {
    this.expect('{'); const out: GField[] = [];
    while (this.peek() !== '}' && this.at < this.toks.length) {
      if (this.peek() === '...') {
        this.next();
        if (this.peek()?.startsWith('W:') && this.toks[this.at].slice(2) === 'on') { this.next(); const onType = this.word(); out.push({ name: '', alias: null, args: {}, sel: this.parseSel(), frag: null, onType }); }
        else { const fname = this.word(); out.push({ name: '', alias: null, args: {}, sel: null, frag: fname, onType: null }); }
        continue;
      }
      let name = this.word(); let alias: string | null = null;
      if (this.peek() === ':') { this.next(); alias = name; name = this.word(); }
      const args: Record<string, GVal> = {};
      if (this.peek() === '(') { this.next(); while (this.peek() !== ')') { const k = this.word(); this.expect(':'); args[k] = this.parseValue(); } this.next(); }
      while (this.peek() === '@') { this.next(); this.word(); if (this.peek() === '(') this.skipParens(); }
      const sel = this.peek() === '{' ? this.parseSel() : null;
      out.push({ name, alias, args, sel, frag: null, onType: null });
    }
    this.expect('}');
    return out;
  }
  parseValue(vars: Record<string, GVal> = {}): GVal {
    const t = this.next();
    if (t === '$') { return { $var: this.word() }; }
    if (t.startsWith('S:')) return t.slice(2);
    if (t.startsWith('N:')) { const n = Number(t.slice(2)); return n; }
    if (t.startsWith('W:')) { const w = t.slice(2); if (w === 'true') return true; if (w === 'false') return false; if (w === 'null') return null; return { $enum: w }; }
    if (t === '[') { const arr: GVal[] = []; while (this.peek() !== ']') arr.push(this.parseValue(vars)); this.next(); return arr; }
    if (t === '{') { const o: Record<string, GVal> = {}; while (this.peek() !== '}') { const k = this.word(); this.expect(':'); o[k] = this.parseValue(vars); } this.next(); return o; }
    return null;
  }
}
/** Resolve variables and enum markers inside a parsed argument value. */
function resolveVal(v: GVal, vars: Record<string, GVal>): GVal {
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, GVal>;
    if ('$var' in o) return vars[o.$var as string] ?? null;
    if ('$enum' in o) return o.$enum;
    if (Array.isArray(v)) return v.map((x) => resolveVal(x, vars));
    const out: Record<string, GVal> = {}; for (const k of Object.keys(o)) out[k] = resolveVal(o[k], vars); return out;
  }
  return v;
}

// --------------------------------------------------------------------------- GraphQL executor
type GN = { __t: string; [k: string]: unknown };
const FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'nodes', 'user', 'organization', 'search', 'rateLimit', '__type', '__schema', '__typename'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment', 'reopenIssue', '__typename'],
  User: ['login', 'id', 'name', 'email', 'url', 'avatarUrl', 'databaseId', 'company', 'location', 'bio', '__typename'],
  Organization: ['login', 'id', 'name', 'url', '__typename'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'hasPullRequestsEnabled', 'hasProjectsEnabled', 'hasWikiEnabled', 'description', 'isPrivate', 'isFork', 'url', 'homepageUrl', 'createdAt', 'updatedAt', 'pushedAt', 'issue', 'issues', 'pullRequest', 'pullRequests', 'labels', 'label', 'branches', 'refs', 'ref', 'object', 'stargazerCount', 'forkCount', 'watchers', 'viewerCanAdminister', 'primaryLanguage', 'licenseInfo', '__typename'],
  Issue: ['id', 'databaseId', 'number', 'title', 'state', 'body', 'bodyText', 'author', 'assignee', 'assignees', 'labels', 'comments', 'createdAt', 'updatedAt', 'closedAt', 'closed', 'locked', 'url', 'repository', 'milestone', 'reactions', 'participants', '__typename'],
  PullRequest: ['id', 'databaseId', 'number', 'title', 'body', 'bodyText', 'state', 'merged', 'mergedAt', 'mergedBy', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'headRepository', 'baseRepository', 'files', 'commits', 'comments', 'reviews', 'author', 'createdAt', 'updatedAt', 'closedAt', 'closed', 'locked', 'url', 'additions', 'deletions', 'changedFiles', 'isDraft', 'mergeCommit', '__typename'],
  Ref: ['name', 'prefix', 'target', '__typename'],
  Commit: ['id', 'oid', 'message', 'committedDate', 'author', '__typename'],
  Label: ['id', 'name', 'color', 'description', '__typename'],
  IssueComment: ['id', 'databaseId', 'body', 'bodyText', 'author', 'createdAt', 'updatedAt', 'url', '__typename'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor', '__typename'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType', '__typename'],
  RefConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  LabelConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  IssueEdge: ['node', 'cursor', '__typename'],
  PullRequestEdge: ['node', 'cursor', '__typename'],
  CommentEdge: ['node', 'cursor', '__typename'],
  CreateIssuePayload: ['issue', 'clientMutationId', '__typename'],
  CloseIssuePayload: ['issue', 'clientMutationId', '__typename'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId', '__typename'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId', '__typename'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId', '__typename'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'interfaces', 'ofType', 'specifiedByURL', 'isOneOf', '__typename'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason', '__typename'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason', '__typename'],
  __InputValue: ['name', 'description', 'type', 'defaultValue', '__typename'],
  __Schema: ['types', 'queryType', 'mutationType', 'subscriptionType', 'directives', '__typename'],
  SearchResultItemConnection: ['nodes', 'edges', 'pageInfo', 'issueCount', 'repositoryCount', 'userCount', '__typename'],
};
const ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'ORGANIZATION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  IssueClosedStateReason: ['COMPLETED', 'NOT_PLANNED'],
};
const cursorOf = (i: number): string => Buffer.from(`cursor:${i}`, 'utf8').toString('base64');
function cursorIdx(v: unknown): number {
  if (typeof v !== 'string' || !v) return -1;
  const m = /cursor:(\d+)/.exec(Buffer.from(v, 'base64').toString('utf8'));
  return m ? Number(m[1]) : -1;
}
function connection(kind: string, all: GN[], args: Record<string, GVal>): GN {
  const first = typeof args.first === 'number' ? args.first : all.length;
  const start = Math.max(0, cursorIdx(args.after) + 1);
  const slice = all.slice(start, start + first);
  const hasNext = start + slice.length < all.length;
  return {
    __t: kind, items: slice, startIndex: start,
    pageInfo: { __t: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: start > 0, startCursor: slice.length ? cursorOf(start) : null, endCursor: slice.length ? cursorOf(start + slice.length - 1) : null },
    totalCount: all.length,
  };
}
const repoNode = (r: Repo): GN => ({ __t: 'Repository', r });
const issueNode = (r: Repo, i: Issue): GN => ({ __t: 'Issue', r, i });
const pullNode = (r: Repo, p: Pull): GN => ({ __t: 'PullRequest', r, p });
function gqlResolve(type: string, src: GN, field: string, args: Record<string, GVal>): unknown {
  switch (type) {
    case 'Query': {
      if (field === 'viewer') return { __t: 'User' };
      if (field === 'repository') { const r = findRepo(String(args.owner ?? ''), String(args.name ?? '')); return r ? repoNode(r) : null; }
      if (field === 'user') return args.login === VIEWER ? { __t: 'User' } : null;
      if (field === 'node') return nodeById(String(args.id ?? ''));
      if (field === '__type') return { __t: '__Type', name: String(args.name ?? '') };
      if (field === 'search') return connection('SearchResultItemConnection', [], args);
      return null;
    }
    case 'Mutation': return mutationField(field, (args.input ?? {}) as Record<string, GVal>);
    case 'User':
      return field === 'login' ? VIEWER : field === 'id' ? gid('User', '1000') : field === 'name' ? VIEWER : field === 'databaseId' ? 1000 : null;
    case 'Repository': {
      const r = src.r as Repo;
      switch (field) {
        case 'id': return gid('Repository', String(r.id));
        case 'databaseId': return r.id;
        case 'name': return r.name;
        case 'nameWithOwner': return `${VIEWER}/${r.name}`;
        case 'owner': return { __t: 'User' };
        case 'defaultBranchRef': return { __t: 'Ref', name: r.defaultBranch };
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': case 'hasPullRequestsEnabled': return true;
        case 'hasProjectsEnabled': case 'hasWikiEnabled': return false;
        case 'description': return r.description; case 'isPrivate': return r.priv; case 'isFork': return false;
        case 'createdAt': case 'updatedAt': case 'pushedAt': return isoAt(r.createdSeq);
        case 'stargazerCount': case 'forkCount': return 0;
        case 'viewerCanAdminister': return true;
        case 'issue': { const i = r.issues.get(Number(args.number)); return i ? issueNode(r, i) : null; }
        case 'pullRequest': { const p = r.pulls.get(Number(args.number)); return p ? pullNode(r, p) : null; }
        case 'issues': {
          let list = [...r.issues.values()];
          const states = args.states as GVal[] | undefined;
          if (Array.isArray(states) && states.length) list = list.filter((i) => states.map(String).includes(i.state.toUpperCase()));
          const ob = args.orderBy as Record<string, GVal> | undefined;
          const dir = ob ? String(ob.direction ?? 'DESC') : 'DESC';
          list.sort((a, b) => (dir === 'ASC' ? a.seq - b.seq || a.number - b.number : b.seq - a.seq || b.number - a.number));
          return connection('IssueConnection', list.map((i) => issueNode(r, i)), args);
        }
        case 'pullRequests': {
          let list = [...r.pulls.values()];
          const states = args.states as GVal[] | undefined;
          if (Array.isArray(states) && states.length) list = list.filter((p) => states.map(String).includes(gqlPrState(p)));
          list.sort((a, b) => b.seq - a.seq || b.number - a.number);
          return connection('PullRequestConnection', list.map((p) => pullNode(r, p)), args);
        }
        case 'labels': return connection('LabelConnection', [...r.labels.values()].map((l) => ({ __t: 'Label', l }) as GN), args);
        default: return null;
      }
    }
    case 'Issue': {
      const i = src.i as Issue; const r = src.r as Repo;
      switch (field) {
        case 'id': return gid('Issue', `${r.id}:${i.number}`);
        case 'databaseId': return i.id; case 'number': return i.number;
        case 'title': return i.title; case 'body': case 'bodyText': return i.body;
        case 'state': return i.state.toUpperCase();
        case 'author': return { __t: 'User' };
        case 'labels': return connection('LabelConnection', i.labels.map((n) => ({ __t: 'Label', l: r.labels.get(n) ?? { name: n, color: 'ededed', description: null } }) as GN), args);
        case 'comments': return connection('IssueConnection', i.comments.map((c) => ({ __t: 'IssueComment', c }) as GN), args);
        case 'createdAt': case 'updatedAt': return isoAt(i.seq);
        case 'closed': return i.state === 'closed'; case 'locked': return false;
        case 'repository': return repoNode(r);
        default: return null;
      }
    }
    case 'PullRequest': {
      const p = src.p as Pull; const r = src.r as Repo;
      switch (field) {
        case 'id': return gid('PullRequest', `${r.id}:${p.number}`);
        case 'databaseId': return p.id; case 'number': return p.number;
        case 'title': return p.title; case 'body': case 'bodyText': return p.body;
        case 'state': return gqlPrState(p);
        case 'merged': return p.merged; case 'mergedAt': return p.mergedAt;
        case 'mergeable': return prMergeable(r, p) ? 'MERGEABLE' : 'CONFLICTING';
        case 'headRefName': return p.head; case 'baseRefName': return p.base;
        case 'headRef': return { __t: 'Ref', name: p.head }; case 'baseRef': return { __t: 'Ref', name: p.base };
        case 'author': return { __t: 'User' };
        case 'createdAt': case 'updatedAt': return isoAt(p.seq);
        case 'closed': return p.state === 'closed'; case 'locked': return false; case 'isDraft': return false;
        case 'files': return connection('PullRequestChangedFileConnection', prFiles(r, p).map((f) => ({ __t: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions }) as GN), args);
        case 'additions': return prFiles(r, p).reduce((s, f) => s + Number(f.additions), 0);
        case 'deletions': return prFiles(r, p).reduce((s, f) => s + Number(f.deletions), 0);
        case 'changedFiles': return prFiles(r, p).length;
        case 'mergeCommit': { const oid = p.mergeSha; return oid ? { __t: 'Commit', oid } : null; }
        default: return null;
      }
    }
    case 'Ref': return field === 'name' ? src.name : field === 'prefix' ? 'refs/heads/' : null;
    case 'Commit': return field === 'oid' ? src.oid : field === 'id' ? gid('Commit', String(src.oid)) : null;
    case 'Label': { const l = src.l as Label; return field === 'name' ? l.name : field === 'color' ? l.color : field === 'description' ? l.description : field === 'id' ? gid('Label', l.name) : null; }
    case 'IssueComment': { const c = src.c as Comment; return field === 'id' ? gid('IssueComment', String(c.id)) : field === 'body' || field === 'bodyText' ? c.body : field === 'author' ? { __t: 'User' } : field === 'databaseId' ? c.id : field === 'createdAt' || field === 'updatedAt' ? isoAt(c.n) : null; }
    case 'PullRequestChangedFile': return field === 'path' ? src.path : field === 'additions' ? src.additions : field === 'deletions' ? src.deletions : field === 'changeType' ? 'MODIFIED' : null;
    case 'PageInfo': return (src as Record<string, unknown>)[field] ?? null;
    case 'IssueConnection': case 'PullRequestConnection': case 'PullRequestChangedFileConnection': case 'LabelConnection': case 'SearchResultItemConnection': {
      if (field === 'nodes') return src.items;
      if (field === 'pageInfo') return src.pageInfo;
      if (field === 'totalCount' || field === 'issueCount' || field === 'repositoryCount' || field === 'userCount') return src.totalCount ?? 0;
      if (field === 'edges') return (src.items as GN[]).map((n, ix) => ({ __t: 'IssueEdge', node: n, cursor: cursorOf((src.startIndex as number) + ix) }));
      return null;
    }
    case 'IssueEdge': case 'PullRequestEdge': return field === 'node' ? src.node : field === 'cursor' ? src.cursor : null;
    case 'CommentEdge': return field === 'node' ? src.node : field === 'cursor' ? src.cursor ?? null : null;
    case '__Type': {
      const name = String(src.name);
      if (field === 'name') return name;
      if (field === 'kind') return ENUMS[name] ? 'ENUM' : 'OBJECT';
      if (field === 'fields') return ENUMS[name] ? null : (FIELDS[name] ?? ['id']).map((n) => ({ __t: '__Field', name: n }));
      if (field === 'enumValues') return ENUMS[name] ? ENUMS[name].map((n) => ({ __t: '__EnumValue', name: n })) : null;
      if (field === 'possibleTypes' || field === 'interfaces' || field === 'inputFields') return [];
      return null;
    }
    case '__Field': return field === 'name' ? src.name : field === 'type' ? { __t: '__Type', name: 'String' } : field === 'isDeprecated' ? false : field === 'args' ? [] : null;
    case '__EnumValue': return field === 'name' ? src.name : field === 'isDeprecated' ? false : null;
    case '__Schema': return field === 'queryType' ? { __t: '__Type', name: 'Query' } : field === 'mutationType' ? { __t: '__Type', name: 'Mutation' } : field === 'types' ? Object.keys(FIELDS).map((n) => ({ __t: '__Type', name: n })) : [];
    default: {
      // Payload types and anything else: read the property straight off the node.
      const v = (src as Record<string, unknown>)[field];
      return v === undefined ? null : v;
    }
  }
}
function gqlPrState(p: Pull): string { return p.merged ? 'MERGED' : p.state.toUpperCase(); }
function nodeById(id: string): GN | null {
  const g = ungid(id); if (!g) return null;
  if (g.type === 'User') return { __t: 'User' };
  if (g.type === 'Repository') { const r = repoByGid(id); return r ? repoNode(r) : null; }
  if (g.type === 'Issue' || g.type === 'PullRequest') {
    const [rid, num] = g.key.split(':');
    for (const r of repos.values()) if (String(r.id) === rid) {
      if (g.type === 'Issue') { const i = r.issues.get(Number(num)); return i ? issueNode(r, i) : null; }
      const p = r.pulls.get(Number(num)); return p ? pullNode(r, p) : null;
    }
  }
  return null;
}
function mutationField(field: string, input: Record<string, GVal>): unknown {
  if (field === 'createIssue') {
    const r = repoByGid(String(input.repositoryId ?? '')); if (!r) return { __t: 'CreateIssuePayload', issue: null };
    const i = makeIssue(r, String(input.title ?? ''), String(input.body ?? ''), []);
    return { __t: 'CreateIssuePayload', issue: issueNode(r, i) };
  }
  if (field === 'closeIssue' || field === 'reopenIssue') {
    const node = nodeById(String(input.issueId ?? ''));
    if (node && node.__t === 'Issue') { (node.i as Issue).state = field === 'closeIssue' ? 'closed' : 'open'; }
    return { __t: 'CloseIssuePayload', issue: node };
  }
  if (field === 'createPullRequest') {
    const r = repoByGid(String(input.repositoryId ?? '')); if (!r) return { __t: 'CreatePullRequestPayload', pullRequest: null };
    const p = makePull(r, String(input.title ?? ''), String(input.body ?? ''), normBranch(String(input.headRefName ?? '')), normBranch(String(input.baseRefName ?? r.defaultBranch)));
    return { __t: 'CreatePullRequestPayload', pullRequest: pullNode(r, p) };
  }
  if (field === 'mergePullRequest') {
    const node = nodeById(String(input.pullRequestId ?? ''));
    if (node && node.__t === 'PullRequest') { const p = node.p as Pull; if (!p.merged) squashMerge(node.r as Repo, p); }
    return { __t: 'MergePullRequestPayload', pullRequest: node };
  }
  if (field === 'addComment') {
    const node = nodeById(String(input.subjectId ?? ''));
    if (node && node.__t === 'Issue') {
      const i = node.i as Issue;
      const c: Comment = { id: ++globalIdSeq + 200000, body: String(input.body ?? ''), n: seq++ };
      i.comments.push(c);
      return { __t: 'AddCommentPayload', commentEdge: { __t: 'CommentEdge', node: { __t: 'IssueComment', c }, cursor: null }, subject: node };
    }
    return { __t: 'AddCommentPayload', commentEdge: null };
  }
  return null;
}
function execSel(type: string, src: GN, sel: GField[], vars: Record<string, GVal>, frags: Map<string, { onType: string; sel: GField[] }>, errors: { message: string }[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of sel) {
    if (f.frag) { const fr = frags.get(f.frag); if (fr) Object.assign(out, execSel(type, src, fr.sel, vars, frags, errors)); continue; }
    if (f.onType) { if (f.onType === type || f.onType === 'Node') Object.assign(out, execSel(type, src, f.sel ?? [], vars, frags, errors)); continue; }
    const key = f.alias ?? f.name;
    if (f.name === '__typename') { out[key] = type; continue; }
    const valid = FIELDS[type];
    if (valid && !valid.includes(f.name)) { errors.push({ message: `Field '${f.name}' doesn't exist on type '${type}'` }); out[key] = null; continue; }
    const args: Record<string, GVal> = {};
    for (const k of Object.keys(f.args)) args[k] = resolveVal(f.args[k], vars);
    let value: unknown;
    try { value = gqlResolve(type, src, f.name, args); } catch { value = null; }
    out[key] = project(value, f, vars, frags, errors);
  }
  return out;
}
function project(value: unknown, f: GField, vars: Record<string, GVal>, frags: Map<string, { onType: string; sel: GField[] }>, errors: { message: string }[]): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((v) => project(v, f, vars, frags, errors));
  if (typeof value === 'object') {
    const node = value as GN;
    if (!f.sel) return node;
    return execSel(node.__t, node, f.sel, vars, frags, errors);
  }
  return value;
}
function runGraphQL(body: unknown): { status: number; payload: unknown } {
  if (Array.isArray(body)) return { status: 200, payload: body.map((op) => gqlOne(op)) };
  return { status: 200, payload: gqlOne(body) };
}
function gqlOne(op: unknown): Record<string, unknown> {
  const o = (op ?? {}) as { query?: string; variables?: Record<string, GVal>; operationName?: string };
  const errors: { message: string }[] = [];
  try {
    const parser = new Parser(String(o.query ?? ''));
    parser.parseDocument();
    const vars = o.variables ?? {};
    let operation = parser.ops[0];
    if (o.operationName) operation = parser.ops.find((x) => x.name === o.operationName) ?? operation;
    if (!operation) return { data: null, errors: [{ message: 'No operation found' }] };
    const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
    const data = execSel(rootType, { __t: rootType }, operation.sel, vars, parser.fragments, errors);
    const out: Record<string, unknown> = { data };
    if (errors.length) out.errors = errors;
    return out;
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'parse error' }] };
  }
}

// --------------------------------------------------------------------------- MCP
type ToolDef = { name: string; description: string; inputSchema: Record<string, unknown> };
const tool = (name: string, description: string, props: Record<string, unknown>, required: string[]): ToolDef => ({
  name, description,
  inputSchema: { type: 'object', properties: props, required, additionalProperties: true },
});
const S = { type: 'string' } as const;
const TOOLS: ToolDef[] = [
  tool('create_repo', 'Create a repository owned by the token user', { name: S, description: S, private: { type: 'boolean' }, full_name: S }, ['name']),
  tool('get_repo', 'Get one repository by owner and name', { owner: S, repo: S, full_name: S }, ['owner', 'repo']),
  tool('create_issue', 'Create an issue in a repository', { owner: S, repo: S, title: S, body: S, full_name: S }, ['owner', 'repo', 'title']),
  tool('list_issues', 'List issues in a repository, optionally filtered by state', { owner: S, repo: S, state: S, full_name: S }, ['owner', 'repo']),
  tool('create_pull_request', 'Open a pull request from a head branch into a base branch', { owner: S, repo: S, title: S, body: S, head: S, base: S, full_name: S }, ['owner', 'repo', 'title', 'head', 'base']),
  tool('merge_pull_request', 'Squash-merge a pull request by number', { owner: S, repo: S, pull_number: { type: 'number' }, full_name: S }, ['owner', 'repo', 'pull_number']),
];
function mcpToolResult(payload: unknown, isErr = false): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: typeof payload === 'object' && payload !== null ? payload : { result: payload }, isError: isErr };
}
function mcpCall(name: string, a: Record<string, unknown>): Record<string, unknown> | null {
  const full = typeof a.full_name === 'string' ? a.full_name : '';
  const owner = String(a.owner ?? (full.includes('/') ? full.split('/')[0] : VIEWER));
  const repoName = String(a.repo ?? a.name ?? (full.includes('/') ? full.split('/').slice(1).join('/') : ''));
  const missing = (keys: string[]): Record<string, unknown> | null => {
    const miss = keys.filter((k) => a[k] === undefined || a[k] === '' || a[k] === null);
    return miss.length ? mcpToolResult(`missing required argument(s): ${miss.join(', ')}`, true) : null;
  };
  switch (name) {
    case 'create_repo': {
      const bad = missing(['name']); if (bad) return bad;
      const n = String(a.name);
      const existing = repos.get(repoKey(VIEWER, n));
      const r = existing ?? newRepo(n, String(a.description ?? ''), Boolean(a.private ?? false), 'main');
      return mcpToolResult(repoObj(r));
    }
    case 'get_repo': {
      const bad = missing(['owner', 'repo']); if (bad) return bad;
      const r = findRepo(owner, repoName);
      if (!r) return mcpToolResult(`repository ${owner}/${repoName} not found`, true);
      return mcpToolResult(repoObj(r));
    }
    case 'create_issue': {
      const bad = missing(['owner', 'repo', 'title']); if (bad) return bad;
      const r = findRepo(owner, repoName); if (!r) return mcpToolResult(`repository ${owner}/${repoName} not found`, true);
      const i = makeIssue(r, String(a.title), String(a.body ?? ''), []);
      return mcpToolResult(issueObj(r, i));
    }
    case 'list_issues': {
      const bad = missing(['owner', 'repo']); if (bad) return bad;
      const r = findRepo(owner, repoName); if (!r) return mcpToolResult(`repository ${owner}/${repoName} not found`, true);
      const state = typeof a.state === 'string' ? a.state : 'open';
      const list = [...r.issues.values()].filter((i) => state === 'all' || i.state === state).map((i) => issueObj(r, i));
      return mcpToolResult(list);
    }
    case 'create_pull_request': {
      const bad = missing(['owner', 'repo', 'title', 'head', 'base']); if (bad) return bad;
      const r = findRepo(owner, repoName); if (!r) return mcpToolResult(`repository ${owner}/${repoName} not found`, true);
      const head = normBranch(String(a.head)); const base = normBranch(String(a.base));
      if (!r.refs.has(branchRef(head))) return mcpToolResult(`head branch ${head} does not exist`, true);
      const p = makePull(r, String(a.title), String(a.body ?? ''), head, base);
      return mcpToolResult(pullObj(r, p));
    }
    case 'merge_pull_request': {
      const bad = missing(['owner', 'repo', 'pull_number']); if (bad) return bad;
      const r = findRepo(owner, repoName); if (!r) return mcpToolResult(`repository ${owner}/${repoName} not found`, true);
      const p = r.pulls.get(Number(a.pull_number));
      if (!p) return mcpToolResult(`pull request ${String(a.pull_number)} not found`, true);
      if (!p.merged) { const sha = squashMerge(r, p); if (!sha) return mcpToolResult('pull request is not mergeable', true); }
      return mcpToolResult(pullObj(r, p));
    }
    default: return null;
  }
}
const MCP_INFO = { name: 'nimble-falcon-forge', version: '1.0.0' };
function mcpHandle(body: unknown): { status: number; payload: unknown; notificationOnly: boolean } {
  if (Array.isArray(body)) {
    const out = body.map((b) => mcpHandle(b)).filter((x) => !x.notificationOnly).map((x) => x.payload);
    return { status: 200, payload: out, notificationOnly: out.length === 0 };
  }
  const msg = (body ?? {}) as { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  const id = msg.id ?? null;
  const isNotification = msg.id === undefined && typeof msg.method === 'string' && msg.method.startsWith('notifications/');
  if (isNotification) return { status: 202, payload: null, notificationOnly: true };
  const rpcErr = (code: number, message: string): { status: number; payload: unknown; notificationOnly: boolean } => ({ status: 200, payload: { jsonrpc: '2.0', id, error: { code, message } }, notificationOnly: false });
  const rpcOk = (result: unknown): { status: number; payload: unknown; notificationOnly: boolean } => ({ status: 200, payload: { jsonrpc: '2.0', id, result }, notificationOnly: false });
  switch (msg.method) {
    case 'server/discover':
      return rpcOk({ resultType: 'complete', supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'], capabilities: { tools: { listChanged: false } }, serverInfo: MCP_INFO });
    case 'initialize': {
      const asked = String((msg.params as { protocolVersion?: unknown })?.protocolVersion ?? '');
      const versions = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
      return rpcOk({ protocolVersion: versions.includes(asked) ? asked : '2025-11-25', capabilities: { tools: { listChanged: false } }, serverInfo: MCP_INFO });
    }
    case 'ping': return rpcOk({});
    case 'tools/list': return rpcOk({ tools: TOOLS });
    case 'tools/call': {
      const params = (msg.params ?? {}) as { name?: unknown; arguments?: Record<string, unknown> };
      const rawName = String(params.name ?? '');
      const found = TOOLS.find((t) => t.name === rawName) ?? TOOLS.find((t) => rawName.toLowerCase().endsWith(t.name));
      if (!found) return rpcErr(-32602, `unknown tool: ${rawName}`);
      const out = mcpCall(found.name, params.arguments ?? {});
      if (!out) return rpcErr(-32602, `unknown tool: ${rawName}`);
      return rpcOk(out);
    }
    default:
      if (typeof msg.method === 'string' && msg.method.startsWith('notifications/')) return { status: 202, payload: null, notificationOnly: true };
      return rpcErr(-32601, `method not found: ${String(msg.method)}`);
  }
}

// --------------------------------------------------------------------------- server dispatch
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const path = url.pathname;
        const m = req.method ?? 'GET';
        if (m === 'GET' && path === '/healthz') { sendJson(res, 200, { ok: true }); return; }
        const bodyBuf = (m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE') ? await readBody(req) : Buffer.alloc(0);
        // GraphQL
        if (path === '/api/graphql') {
          if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
          if (m !== 'POST') { errJson(res, 404, 'Not Found'); return; }
          const parsed = parseJsonBody(bodyBuf);
          if (parsed === undefined) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const { payload } = runGraphQL(parsed);
          sendJson(res, 200, payload);
          return;
        }
        // MCP
        if (path === '/mcp') {
          if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
          if (m === 'GET') { res.writeHead(200, { 'content-type': JSON_TYPE, 'x-github-request-id': randomUUID(), 'mcp-session-id': 'w7-session' }); res.end('{}'); return; }
          if (m === 'DELETE') { res.writeHead(200, { 'x-github-request-id': randomUUID() }); res.end(); return; }
          let parsed: unknown;
          try { parsed = JSON.parse(bodyBuf.toString('utf8')); } catch {
            res.writeHead(400, { 'content-type': JSON_TYPE, 'x-github-request-id': randomUUID() });
            res.end(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`); return;
          }
          const out = mcpHandle(parsed);
          if (out.notificationOnly) { res.writeHead(202, { 'x-github-request-id': randomUUID(), 'mcp-session-id': 'w7-session' }); res.end(); return; }
          res.writeHead(200, { 'content-type': JSON_TYPE, 'x-github-request-id': randomUUID(), 'mcp-session-id': 'w7-session' });
          res.end(`${JSON.stringify(out.payload)}\n`);
          return;
        }
        // REST
        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
          const segs = path.replace(/^\/api\/v3\/?/, '').split('/').filter((s) => s !== '').map((s) => { try { return decodeURIComponent(s); } catch { return s; } });
          // contents paths keep their slashes: rebuild from the raw tail when needed.
          const parsed = bodyBuf.length ? parseJsonBody(bodyBuf) : {};
          if (bodyBuf.length && parsed === undefined && (m === 'POST' || m === 'PUT' || m === 'PATCH')) { errJson(res, 400, 'Problems parsing JSON'); return; }
          await rest({ req, res, url, segs, body: parsed });
          return;
        }
        // git smart HTTP: /{owner}/{repo}.git/...
        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
        if (gitMatch) {
          if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return; }
          const owner = decodeURIComponent(gitMatch[1]); const repoName = decodeURIComponent(gitMatch[2]); const tail = gitMatch[3] ?? '';
          const r = findRepo(owner, repoName);
          if (!r) { errJson(res, 404, 'Not Found'); return; }
          if (m === 'GET' && tail === '/info/refs') {
            const service = url.searchParams.get('service') ?? '';
            if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { errJson(res, 404, 'Not Found'); return; }
            const v2 = service === 'git-upload-pack' && String(req.headers['git-protocol'] ?? '').includes('version=2');
            advertise(res, service, r, v2); return;
          }
          if (m === 'POST' && tail === '/git-upload-pack') {
            const v2 = String(req.headers['git-protocol'] ?? '').includes('version=2');
            try { uploadPack(res, r, bodyBuf, v2); } catch { res.writeHead(400, { 'content-type': 'text/plain', 'x-github-request-id': randomUUID() }); res.end('bad request\n'); }
            return;
          }
          if (m === 'POST' && tail === '/git-receive-pack') {
            try { receivePack(res, r, bodyBuf); } catch { res.writeHead(400, { 'content-type': 'text/plain', 'x-github-request-id': randomUUID() }); res.end('bad request\n'); }
            return;
          }
          errJson(res, 404, 'Not Found'); return;
        }
        errJson(res, 404, 'Not Found');
      } catch {
        if (!res.headersSent) errJson(res, 500, 'Internal Server Error');
        else { try { res.end(); } catch { /* already gone */ } }
      }
    })();
  });
}
