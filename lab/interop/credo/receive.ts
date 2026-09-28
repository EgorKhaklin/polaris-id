// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/**
 * An unmodified Credo agent receiving one SD-JWT VC over OpenID4VCI 1.0 (pre-authorized code)
 * from the lab issuer in lab/strategy/005/issuer/. The issuer half of 005 section 9 step 2.
 *
 *   OFFER=<openid-credential-offer://...>  ISSUER_TLS=<issuer tls.pem>  ISSUER_CA=<issuer CA pem>
 *   OUT=<dir>  node receive.ts
 *
 * Only Credo's public holder API: resolveCredentialOffer, requestToken, requestCredentials,
 * with a binding resolver that answers with a key Credo's own KMS generated. The credential is
 * then stored through agent.sdJwtVc.store, which is what a wallet does with it. Exit 0 only if
 * a credential came back and Credo stored it.
 */
import { spawn } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const OFFER = process.env.OFFER ?? ''
const OUT = process.env.OUT ?? path.join(process.cwd(), 'receive-out')
if (!OFFER) throw new Error('OFFER is required')

if (!process.env.__CREDO_RECEIVE_CHILD) {
  // The issuer's TLS certificate is self-signed; trusting it is the same registration
  // present.ts performs for the verifier's.
  const child = spawn(process.execPath, [...process.execArgv, ...process.argv.slice(1)], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: process.env.ISSUER_TLS ?? '', __CREDO_RECEIVE_CHILD: '1' },
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
  const { Agent, ConsoleLogger, DependencyManager, InjectionSymbols, Kms, LogLevel, X509Module } = await import('@credo-ts/core')
  const { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } = await import(
    '@credo-ts/node'
  )
  const { OpenId4VcModule } = await import('@credo-ts/openid4vc')
  const { MemoryStorageService } = await import('./MemoryStorageService.ts')
  mkdirSync(OUT, { recursive: true })

  const wire: unknown[] = []
  const loggingFetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const res = await agentDependencies.fetch(input as never, init as never)
    const text = await res.clone().text().catch(() => '<unreadable>')
    wire.push({
      request: { method: init?.method ?? 'GET', url, headers: init?.headers, body: init?.body === undefined ? undefined : String(init.body) },
      response: { status: res.status, body: text },
    })
    console.log(`wire ${init?.method ?? 'GET'} ${url} -> ${res.status}`)
    return res as never
  }

  const dm = new DependencyManager()
  dm.registerInstance(InjectionSymbols.StorageService, new MemoryStorageService())
  const agent = new Agent(
    {
      config: { logger: new ConsoleLogger(LogLevel.warn), autoUpdateStorageOnStartup: true },
      dependencies: { ...agentDependencies, fetch: loggingFetch as never },
      modules: {
        kms: new Kms.KeyManagementModule({
          backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
        }),
        // The issuer's CA, the registration a wallet makes to trust an x5c-signed credential.
        x509: new X509Module({ trustedCertificates: process.env.ISSUER_CA ? [readFileSync(process.env.ISSUER_CA, 'utf8')] : [] }),
        openid4vc: new OpenId4VcModule(),
      },
    },
    dm
  )
  await agent.initialize()
  const holderKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  console.log(`holder key created by Credo KMS: ${JSON.stringify(holderKey.publicJwk)}`)

  let outcome: Record<string, unknown> = { stored: false }
  try {
    const resolved = await agent.openid4vc.holder.resolveCredentialOffer(OFFER)
    const token = await agent.openid4vc.holder.requestToken({ resolvedCredentialOffer: resolved })
    const result = await agent.openid4vc.holder.requestCredentials({
      resolvedCredentialOffer: resolved,
      ...token,
      credentialBindingResolver: () => ({
        method: 'jwk',
        keys: [Kms.PublicJwk.fromPublicJwk(holderKey.publicJwk as never)],
      }),
    })
    const first = result.credentials[0]
    if (!first) throw new Error('no credential in the response')
    await agent.sdJwtVc.store({ record: first.record as never })
    const stored = await agent.sdJwtVc.getAll()
    outcome = {
      stored: stored.length === 1,
      vct: stored[0]?.getTags().vct,
      claims: stored[0]?.firstCredential.prettyClaims,
      compact: stored[0]?.firstCredential.compact,
      holder_jwk: holderKey.publicJwk,
    }
    console.log(`RESULT: credential stored by Credo, vct=${String(outcome.vct)}`)
  } catch (err) {
    outcome = { stored: false, error: String(err) }
    console.log(`RESULT: NOT RECEIVED: ${String(err)}`)
  }
  writeFileSync(path.join(OUT, 'wire.json'), JSON.stringify(wire, null, 2))
  writeFileSync(path.join(OUT, 'outcome.json'), JSON.stringify(outcome, null, 2))
  await agent.shutdown()
  return outcome.stored ? 0 : 1
}
