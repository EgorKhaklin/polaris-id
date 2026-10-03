// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/**
 * present.ts -- an unmodified Credo holder presents an SD-JWT VC to polaris-oid4vp.
 *
 *   npm run present
 *
 * One process, in order:
 *   1. `polaris-oid4vp keygen` makes the verifier's CA, request-signing leaf and TLS cert.
 *   2. An in-memory Credo agent is created. Its own KMS (NodeKeyManagementService)
 *      generates a P-256 holder key. The private half never leaves Credo.
 *   3. lab/interop/waltid/issue_sdjwt_vc.py (unchanged, the walt.id harness's issuer) mints
 *      one SD-JWT VC whose cnf.jwk is that public key; Credo stores it via its public API.
 *   4. `polaris-oid4vp serve --once` is started with the issuer's JWKS. The authorization
 *      request parameters it prints (client_id, request_uri, request_uri_method) become an
 *      openid4vp:// URL.
 *   5. Credo resolves the request (fetching and verifying the signed request object against
 *      the verifier's CA, registered through X509Module `trustedCertificates`), matches the
 *      DCQL query, and accepts: Credo's own code builds the KB-JWT, the JWE and the POST.
 *   6. Both sides' output is written to ./evidence/.
 *
 * Configuration only: nothing in Credo is patched, wrapped or replaced, except that the
 * agent's `fetch` dependency is a logging pass-through so the wire exchange can be saved.
 *
 * Environment:
 *   POLARIS_OID4VP  the verifier CLI       (default: polaris-oid4vp on PATH)
 *   PYTHON          python for the issuer  (default: python3; needs `cryptography`)
 *   PORT            verifier port          (default: 9543)
 *   NODE_EXTRA_CA_CERTS must name run/pki/tls.pem so Node trusts the verifier's TLS
 *   listener; `npm run present` re-executes itself with it set.
 */
import { type ChildProcess, execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const RUN = path.join(HERE, 'run')
const PKI = path.join(RUN, 'pki')
// CONTROL selects a negative control; each must end in a refusal, or the positive run
// proves nothing (a verifier that accepts everything prints the same success line).
//   wrong-issuer    the verifier trusts a different key under the same kid
//   foreign-holder  the credential's cnf is a key Credo does not hold
//   replay          Credo's accepted response is POSTed a second time
//   untrusted-verifier  Credo trusts a different CA than the one that signed the request
const CONTROL = process.env.CONTROL ?? ''
if (CONTROL && !['wrong-issuer', 'foreign-holder', 'replay', 'untrusted-verifier'].includes(CONTROL)) {
  throw new Error(`unknown CONTROL '${CONTROL}'`)
}
// EVIDENCE_DIR records a run somewhere other than evidence/, so walking another Credo version does
// not overwrite the recorded runs.
const EVIDENCE = path.resolve(HERE, process.env.EVIDENCE_DIR ?? 'evidence', CONTROL || 'positive')
const VERIFIER = process.env.POLARIS_OID4VP ?? 'polaris-oid4vp'
const PYTHON = process.env.PYTHON ?? 'python3'
const PORT = Number(process.env.PORT ?? 9543)
const HOST = 'localhost'
const ISSUER_SCRIPT = path.join(HERE, '..', 'waltid', 'issue_sdjwt_vc.py')

const walletLog: string[] = []
function log(line: string) {
  const stamped = `[${new Date().toISOString()}] ${line}`
  walletLog.push(stamped)
  console.log(stamped)
}

// --- 0. keys, and Node's trust in the verifier's TLS listener ---------------------------
if (!process.env.__CREDO_HARNESS_CHILD) {
  rmSync(RUN, { recursive: true, force: true })
  mkdirSync(RUN, { recursive: true })
  const keygenOut = execFileSync(
    VERIFIER,
    ['keygen', '--out', PKI, '--host', HOST, '--port', String(PORT)],
    { encoding: 'utf8' }
  )
  writeFileSync(path.join(RUN, 'keygen.txt'), keygenOut)
  // The TLS certificate is self-signed. Node is right to refuse it; registering it as an
  // extra CA is the Node equivalent of walt.id's keytool -importcert step.
  const child = spawn(process.execPath, [...process.execArgv, ...process.argv.slice(1)], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: path.join(PKI, 'tls.pem'), __CREDO_HARNESS_CHILD: '1' },
  })
  child.on('exit', (code) => process.exit(code ?? 1))
} else {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err)
      process.exit(1)
    }
  )
}

async function main(): Promise<number> {
  const { Agent, ConsoleLogger, DependencyManager, InjectionSymbols, Kms, LogLevel, SdJwtVcRecord, X509Module } =
    await import('@credo-ts/core')
  const { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } = await import(
    '@credo-ts/node'
  )
  const { OpenId4VcModule } = await import('@credo-ts/openid4vc')
  const { MemoryStorageService } = await import('./MemoryStorageService.ts')

  mkdirSync(EVIDENCE, { recursive: true })
  const versions = {
    date: new Date().toISOString(),
    node: process.version,
    credo_core: pkgVersion('@credo-ts/core'),
    credo_openid4vc: pkgVersion('@credo-ts/openid4vc'),
    credo_node: pkgVersion('@credo-ts/node'),
    openid4vc_openid4vp: pkgVersion('@openid4vc/openid4vp'),
    openid4vc_oauth2: pkgVersion('@openid4vc/oauth2'),
    sd_jwt_core: pkgVersion('@sd-jwt/core'),
    polaris_oid4vp: execFileSync(PYTHON, ['-c', 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))'], {
      encoding: 'utf8',
    }).trim(),
  }
  log(`versions ${JSON.stringify(versions)}`)

  // --- wire log: a pass-through fetch, registered as the agent's fetch dependency --------
  const wire: unknown[] = []
  const loggingFetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const reqBody = init?.body === undefined ? undefined : String(init.body)
    const res = await agentDependencies.fetch(input as never, init as never)
    const text = await res.clone().text().catch(() => '<unreadable>')
    wire.push({
      request: { method: init?.method ?? 'GET', url, headers: init?.headers, body: reqBody },
      response: { status: res.status, contentType: res.headers.get('content-type'), body: text },
    })
    log(`wire ${init?.method ?? 'GET'} ${url} -> ${res.status}`)
    return res as never
  }

  // --- 2. the holder agent ---------------------------------------------------------------
  const dm = new DependencyManager()
  dm.registerInstance(InjectionSymbols.StorageService, new MemoryStorageService())
  let anchorPem = readFileSync(path.join(PKI, 'anchor.pem'), 'utf8')
  if (CONTROL === 'untrusted-verifier') {
    const other = path.join(RUN, 'other-pki')
    execFileSync(VERIFIER, ['keygen', '--out', other, '--host', HOST, '--port', String(PORT)])
    anchorPem = readFileSync(path.join(other, 'anchor.pem'), 'utf8')
    log('CONTROL untrusted-verifier: Credo trusts an unrelated CA made by a second keygen')
  }
  const agent = new Agent(
    {
      // A fresh in-memory store has no storage-version record, which Credo reads as 0.1 and
      // refuses; askar and drizzle seed it when they create a store. Updating an empty store
      // migrates nothing.
      config: { logger: new ConsoleLogger(logLevel(LogLevel, 'warn')), autoUpdateStorageOnStartup: true },
      dependencies: { ...agentDependencies, fetch: loggingFetch as never },
      modules: {
        kms: new Kms.KeyManagementModule({
          backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
        }),
        // The registration `keygen` tells a counterparty to perform: trust the CA, not the leaf.
        x509: new X509Module({ trustedCertificates: [anchorPem] }),
        openid4vc: new OpenId4VcModule(),
      },
    },
    dm
  )
  await agent.initialize()
  log('credo agent initialized (in-memory storage, NodeKeyManagementService)')

  const holderKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  log(`holder key created by Credo KMS: keyId=${holderKey.keyId} publicJwk=${JSON.stringify(holderKey.publicJwk)}`)
  writeFileSync(
    path.join(RUN, 'holder.json'),
    JSON.stringify({ holder_jwk: CONTROL === 'foreign-holder' ? freshP256Jwk('not-credo') : holderKey.publicJwk })
  )
  if (CONTROL === 'foreign-holder') log('CONTROL foreign-holder: cnf.jwk is a key generated outside Credo')

  // --- 3. the credential -------------------------------------------------------------------
  // Credo 0.7 names an SD-JWT VC issuer only by DID or certificate ("Only did and x5c are
  // supported"), so from 0.7 the issuer signs under a certificate in x5c and the wallet and the
  // verifier both trust the CA that certified it. 0.6 took a bare kid, the recorded runs' JWKS way.
  const [credoMajor, credoMinor] = pkgVersion('@credo-ts/core').split('.').map(Number)
  const X5C_ISSUER = credoMajor > 0 || credoMinor >= 7
  const issuerOut = execFileSync(
    PYTHON,
    [ISSUER_SCRIPT, '--holder-jwk', path.join(RUN, 'holder.json'), '--out', path.join(RUN, 'credential.json'),
      ...(X5C_ISSUER ? ['--x5c'] : [])],
    { encoding: 'utf8' }
  )
  log(`issuer: ${issuerOut.trim().replace(/\n/g, ' | ')}`)
  const minted = JSON.parse(readFileSync(path.join(RUN, 'credential.json'), 'utf8'))
  let issuerTrust: string[]
  if (X5C_ISSUER) {
    agent.x509.config.addTrustedCertificate(minted.issuer_ca_pem)
    writeFileSync(path.join(RUN, 'issuer-ca.pem'), minted.issuer_ca_pem)
    let trustedCa = path.join(RUN, 'issuer-ca.pem')
    if (CONTROL === 'wrong-issuer') {
      const other = path.join(RUN, 'other-issuer')
      execFileSync(VERIFIER, ['keygen', '--out', other, '--host', HOST, '--port', String(PORT)])
      trustedCa = path.join(other, 'anchor.pem')
      log('CONTROL wrong-issuer: the verifier trusts an unrelated CA, not the one that certified the issuer')
    }
    issuerTrust = ['--issuer-trust-anchor', trustedCa]
  } else {
    const trustedIssuerJwks =
      CONTROL === 'wrong-issuer' ? [freshP256Jwk(minted.issuer_jwks[0].kid)] : minted.issuer_jwks
    if (CONTROL === 'wrong-issuer') log('CONTROL wrong-issuer: verifier trusts a different key under the same kid')
    writeFileSync(path.join(RUN, 'issuer-jwks.json'), JSON.stringify(trustedIssuerJwks))
    issuerTrust = ['--issuer-jwks', path.join(RUN, 'issuer-jwks.json')]
  }

  const record = new SdJwtVcRecord({
    credentialInstances: [{ compactSdJwtVc: minted.credential, kmsKeyId: holderKey.keyId }],
  })
  await agent.sdJwtVc.store({ record })
  const stored = await agent.sdJwtVc.getAll()
  log(`credo stored ${stored.length} SD-JWT VC; vct=${stored[0]?.getTags().vct} claims=${JSON.stringify(stored[0]?.firstCredential.prettyClaims)}`)

  // --- 4. the verifier ---------------------------------------------------------------------
  const verifierLines: string[] = []
  const verifier = spawn(
    VERIFIER,
    [
      'serve', '--pki', PKI, '--host', HOST, '--bind', '127.0.0.1', '--port', String(PORT),
      ...issuerTrust, '--once', '--verbose',
    ],
    { env: { ...process.env, PYTHONUNBUFFERED: '1' } }
  )
  const onData = (buf: Buffer) => {
    for (const l of buf.toString().split('\n')) if (l.length) verifierLines.push(l)
  }
  verifier.stdout.on('data', onData)
  verifier.stderr.on('data', onData)

  const params = await waitForParams(verifierLines, verifier)
  const requestUrl = `openid4vp://authorize?${new URLSearchParams(params).toString()}`
  log(`authorization request: ${requestUrl}`)

  let outcome: Record<string, unknown> = {}
  let exitCode = 1
  try {
    // --- 5. resolve and accept, both entirely Credo's code ---------------------------------
    const resolved = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(requestUrl)
    log(
      `resolved: clientIdPrefix=${resolved.verifier.clientIdPrefix} effectiveClientId=${resolved.verifier.effectiveClientId} ` +
        `response_mode=${resolved.authorizationRequestPayload.response_mode} dcql.canBeSatisfied=${resolved.dcql?.queryResult.can_be_satisfied}`
    )
    saveEvidence(
      'resolved-request.json',
      JSON.stringify(
        {
          verifier: resolved.verifier,
          signedAuthorizationRequest: resolved.signedAuthorizationRequest
            ? { header: resolved.signedAuthorizationRequest.header, payload: resolved.signedAuthorizationRequest.payload, signer: { method: resolved.signedAuthorizationRequest.signer.method } }
            : undefined,
          authorizationRequestPayload: resolved.authorizationRequestPayload,
          dcqlQueryResult: resolved.dcql?.queryResult,
        },
        null,
        2
      )
    )
    if (!resolved.dcql) throw new Error('resolved request carries no DCQL query')
    const credentials = agent.openid4vc.holder.selectCredentialsForDcqlRequest(resolved.dcql.queryResult)
    const accepted = await agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolved.authorizationRequestPayload,
      dcql: { credentials },
    })
    const serverResponse = accepted.serverResponse as { status?: number; body?: unknown } | undefined
    log(`accept returned ok=${accepted.ok} serverResponse=${JSON.stringify(serverResponse)}`)
    outcome = {
      credo: 'accept returned',
      ok: accepted.ok,
      serverResponse,
      redirectUri: (accepted as { redirectUri?: string }).redirectUri,
      // What Credo encrypted, before encryption: the vp_token it built.
      authorizationResponsePayload: accepted.authorizationResponsePayload,
    }
    exitCode = accepted.ok ? 0 : 1
    if (CONTROL === 'replay') {
      const first = (wire as Array<{ request: { url: string; body?: string } }>).find((w) =>
        w.request.url.endsWith('/response')
      )
      if (!first?.request.body) throw new Error('no response POST captured to replay')
      const again = await agentDependencies.fetch(first.request.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: first.request.body,
      })
      const againBody = await again.text()
      log(`CONTROL replay: second POST of the identical response -> ${again.status} ${againBody}`)
      outcome.replay = { status: again.status, body: againBody }
    }
  } catch (err) {
    const e = err as Error & Record<string, unknown>
    log(`credo threw: ${e.name}: ${e.message}`)
    outcome = { credo: 'threw', name: e.name, message: e.message, detail: serialiseError(e) }
  }

  await delay(1000)
  verifier.kill('SIGINT')
  await new Promise((r) => verifier.once('exit', r))
  const verdictLine = verifierLines.find((l) => l.trim().startsWith('<-')) ?? '(the verifier printed no verdict line)'
  log(`verifier verdict: ${verdictLine.trim()}`)

  saveEvidence('verifier.log', `${verifierLines.join('\n')}\n`)
  saveEvidence('wallet.log', `${walletLog.join('\n')}\n`)
  saveEvidence('wire.json', JSON.stringify(wire, null, 2))
  saveEvidence(
    'outcome.json',
    JSON.stringify({ versions, requestUrl, verifierVerdict: verdictLine.trim(), ...outcome }, null, 2)
  )
  await agent.shutdown()
  const verdicts = verifierLines.filter((l) => l.trim().startsWith('<-')).map((l) => l.trim())
  const authentic = /^<- 200 authentic/.test(verdicts[0] ?? '')
  if (!CONTROL) {
    console.log(authentic ? '\nRESULT: ACCEPTED by polaris-oid4vp' : '\nRESULT: NOT accepted (see evidence/)')
    return authentic && exitCode === 0 ? 0 : 1
  }
  // A control passes when the verifier refused what it should refuse.
  const refused =
    CONTROL === 'untrusted-verifier'
      ? outcome.credo === 'threw' && verdicts.length === 0 && !wire.some((w) => (w as { request: { url: string } }).request.url.endsWith('/response'))
      : CONTROL === 'replay'
      ? authentic &&
        verdicts.length === 2 &&
        /^<- 400 refused/.test(verdicts[1]) &&
        (outcome.replay as { status: number } | undefined)?.status === 400
      : !authentic && verdicts.length > 0 && /refused/.test(verdicts[0])
  console.log(`\nCONTROL ${CONTROL}: ${refused ? 'REFUSED as it must be' : 'NOT REFUSED: the positive result is void'}`)
  return refused ? 0 : 1
}

async function waitForParams(lines: string[], proc: ChildProcess): Promise<Record<string, string>> {
  for (let i = 0; i < 100; i++) {
    const at = lines.findIndex((l) => l.startsWith('authorization request parameters:'))
    if (at >= 0 && lines.length >= at + 4) {
      const out: Record<string, string> = {}
      for (const l of lines.slice(at + 1, at + 4)) {
        const [k, v] = l.trim().split(/\s+/, 2)
        out[k] = v
      }
      return out
    }
    if (proc.exitCode !== null) break
    await delay(100)
  }
  throw new Error(`verifier did not print its authorization request parameters:\n${lines.join('\n')}`)
}

// Credo 0.7 renamed the log levels (LogLevel.warn became LogLevel.Warn); this reads either.
function logLevel(levels: object, name: string): number {
  const table = levels as Record<string, number>
  return table[name[0].toUpperCase() + name.slice(1)] ?? table[name]
}

function pkgVersion(name: string): string {
  const p = path.join(HERE, 'node_modules', name, 'package.json')
  return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')).version : 'not installed'
}

function serialiseError(e: unknown): unknown {
  if (!(e instanceof Error)) return e
  const out: Record<string, unknown> = { name: e.name, message: e.message }
  for (const k of Object.getOwnPropertyNames(e)) if (k !== 'stack') out[k] = (e as never)[k]
  if (e.cause) out.cause = serialiseError(e.cause)
  out.stack = e.stack?.split('\n').slice(0, 12)
  return out
}

/** A P-256 public JWK for a key nobody in this run holds the private half of. */
function freshP256Jwk(kid: string) {
  const out = execFileSync(
    PYTHON,
    [
      '-c',
      [
        'import base64, json, sys',
        'from cryptography.hazmat.primitives.asymmetric import ec',
        'n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()',
        'b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")',
        'print(json.dumps({"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y), "kid": sys.argv[1]}))',
      ].join('\n'),
      kid,
    ],
    { encoding: 'utf8' }
  )
  return JSON.parse(out)
}

/** Evidence is meant to be committed: paths are made relative to this directory. */
function saveEvidence(name: string, text: string) {
  writeFileSync(path.join(EVIDENCE, name), text.split(HERE).join('.'))
}

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}
