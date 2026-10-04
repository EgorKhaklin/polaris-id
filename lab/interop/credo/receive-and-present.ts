// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/**
 * An unmodified Credo agent that receives a wallet copy over OpenID4VCI 1.0 from polaris_web and
 * then presents it over OpenID4VP 1.0, in ONE process: Credo's storage here is in memory, so the
 * credential it received exists only while this process lives. lab/strategy/005 step S6, driven
 * by lab/strategy/005/product/present.py, which revokes the credential between presentations.
 *
 *   OFFER=<openid-credential-offer://...>   the operator's offer
 *   ISSUER_CA=<pem>                         the product's TEST wallet-copy anchor (issuer x5c)
 *   VERIFIER_CA=<pem>                       the verifier's request-object CA (client x509_hash)
 *   NODE_EXTRA_CA_CERTS=<pem bundle>        the product's and the verifier's TLS certificates
 *   node receive-and-present.ts
 *
 * Protocol on stdio, one JSON object per line: after receiving it prints
 *   {"ready": true, "stored": true, ...}
 * then reads openid4vp:// request URLs from stdin, one per line, and answers each with
 *   {"presented": true, "ok": ..., "serverResponse": ...}
 * until stdin closes. Only Credo's public holder API is used: resolveCredentialOffer,
 * requestToken, requestCredentials, sdJwtVc.store, resolveOpenId4VpAuthorizationRequest,
 * selectCredentialsForDcqlRequest, acceptOpenId4VpAuthorizationRequest.
 */
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'

const OFFER = process.env.OFFER ?? ''
if (!OFFER) throw new Error('OFFER is required')

const say = (obj: Record<string, unknown>) => process.stdout.write(JSON.stringify(obj) + '\n')

async function main(): Promise<number> {
  const { Agent, ConsoleLogger, DependencyManager, InjectionSymbols, Kms, LogLevel, X509Module } = await import('@credo-ts/core')
  const { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } = await import('@credo-ts/node')
  const { OpenId4VcModule } = await import('@credo-ts/openid4vc')
  const { MemoryStorageService } = await import('./MemoryStorageService.ts')

  const trusted = [process.env.ISSUER_CA, process.env.VERIFIER_CA]
    .filter((p): p is string => Boolean(p))
    .map((p) => readFileSync(p, 'utf8'))
  const dm = new DependencyManager()
  dm.registerInstance(InjectionSymbols.StorageService, new MemoryStorageService())
  const agent = new Agent(
    {
      config: { logger: new ConsoleLogger((LogLevel as unknown as Record<string, number>)['Error'] ?? (LogLevel as unknown as Record<string, number>)['error']), autoUpdateStorageOnStartup: true },
      dependencies: agentDependencies,
      modules: {
        kms: new Kms.KeyManagementModule({
          backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
        }),
        // Registration a wallet makes: the issuer's CA for the credential's x5c, and the
        // verifier's CA for the request object's x5c.
        x509: new X509Module({ trustedCertificates: trusted }),
        openid4vc: new OpenId4VcModule(),
      },
    },
    dm
  )
  await agent.initialize()
  const holderKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })

  try {
    const resolved = await agent.openid4vc.holder.resolveCredentialOffer(OFFER)
    const token = await agent.openid4vc.holder.requestToken({ resolvedCredentialOffer: resolved })
    const result = await agent.openid4vc.holder.requestCredentials({
      resolvedCredentialOffer: resolved,
      ...token,
      credentialBindingResolver: () => ({ method: 'jwk', keys: [Kms.PublicJwk.fromPublicJwk(holderKey.publicJwk as never)] }),
    })
    const first = result.credentials[0]
    if (!first) throw new Error('no credential in the response')
    await agent.sdJwtVc.store({ record: first.record as never })
    const stored = await agent.sdJwtVc.getAll()
    say({ ready: true, stored: stored.length === 1, vct: stored[0]?.getTags().vct, holder_jwk: holderKey.publicJwk })
  } catch (err) {
    say({ ready: true, stored: false, error: String(err) })
    await agent.shutdown()
    return 1
  }

  const lines = createInterface({ input: process.stdin })
  for await (const line of lines) {
    const requestUrl = line.trim()
    if (!requestUrl) continue
    try {
      const resolved = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(requestUrl)
      if (!resolved.dcql) throw new Error('resolved request carries no DCQL query')
      const credentials = agent.openid4vc.holder.selectCredentialsForDcqlRequest(resolved.dcql.queryResult)
      const accepted = await agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
        authorizationRequestPayload: resolved.authorizationRequestPayload,
        dcql: { credentials },
      })
      say({ presented: true, ok: accepted.ok, serverResponse: accepted.serverResponse ?? null })
    } catch (err) {
      say({ presented: false, error: String(err) })
    }
  }
  await agent.shutdown()
  return 0
}

main().then(
  (code) => process.exit(code),
  (err) => {
    say({ fatal: String(err) })
    process.exit(1)
  }
)
