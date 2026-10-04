// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/**
 * walk.ts -- Credo as the issuer, on a P-256 did:cheqd it registers on a cheqd localnet, and
 * Credo as the holder, presenting to polaris-oid4vp. run.sh drives it; three subcommands:
 *
 *   node walk.ts issue   WORK              the issuer: the DID, the status list, the credential
 *   node walk.ts present WORK URI ANCHOR   the holder: resolves the request and answers it
 *   node walk.ts revoke  WORK              the issuer: a new version of the status list, in which
 *                                          the credential is revoked
 *
 * The issuer. A P-256 key goes into Credo's KMS. The DID document names it as a JsonWebKey2020
 * verification method (authentication and assertionMethod), and @credo-ts/cheqd registers it:
 * Credo signs the ledger payload with that key (the ledger takes ES256 as a DER signature), and
 * the localnet's genesis-funded test account is the fee payer. Credo then makes a Token Status
 * List (statuslist+jwt, signed by the DID's key), publishes it as a DID-Linked Resource of type
 * TokenStatusList, and issues a dc+sd-jwt (vct urn:eudi:pid:1, given_name and family_name
 * selectively disclosable) whose header kid is the key's DID URL (Credo writes it relative to
 * iss: "#key-1") and whose status claim names the resource by its DID URL. All of it through
 * Credo's public API.
 *
 * The holder. Credo resolves the issuer's DID on the localnet and checks the credential's
 * signature before it keeps it. Then Credo's own OpenID4VP code fetches and checks the request
 * (x509_hash, the CA it trusts for the verifier), matches the DCQL query and sends the encrypted
 * direct_post.jwt.
 *
 * Keys: the walk makes the two P-256 test keys (node:crypto) under WORK and imports them into
 * Credo's KMS in each process, so the issuer can sign again when it revokes. They are test keys
 * of one run and never leave WORK.
 *
 * Environment: CHEQD_RPC, the localnet's RPC (default http://127.0.0.1:26657).
 */
import { generateKeyPairSync, randomInt, randomUUID } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { CheqdDidRegistrar, CheqdDidResolver, CheqdModule } from '@credo-ts/cheqd'
import {
  Agent,
  type ModulesMap,
  ConsoleLogger,
  DependencyManager,
  DidDocument,
  DidsModule,
  InjectionSymbols,
  JsonTransformer,
  Kms,
  LogLevel,
  SdJwtVcRecord,
  TypedArrayEncoder,
  X509Module,
} from '@credo-ts/core'
import { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } from '@credo-ts/node'
import { OpenId4VcModule } from '@credo-ts/openid4vc'

import { MemoryStorageService } from './MemoryStorageService.ts'

const RPC = process.env.CHEQD_RPC ?? 'http://127.0.0.1:26657'
// base_account_1 of cheqd-node's localnet (docker/localnet/gen-network-config.sh and
// import-keys.sh publish it with this mnemonic). It is funded in the localnet's genesis and is
// the fee payer of the ledger writes; it is configuration of a local test chain, not a secret.
const LOCALNET_PAYER =
  'sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright'
const STATUS_LIST_NAME = 'pid-status'
const STATUS_LIST_TYPE = 'TokenStatusList' // the resource type cheqd uses for a Token Status List

type PrivateJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string; d: string }
type Issued = {
  did: string
  didUrl: string
  statusUri: string
  statusIndex: number
  statusListToken: string
  resources: string[]
  credential: string
}

function log(line: string) {
  console.log(`[${new Date().toISOString()}] ${line}`)
}

function newP256(): PrivateJwk {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const { kty, crv, x, y, d } = privateKey.export({ format: 'jwk' })
  return { kty: kty as 'EC', crv: crv as 'P-256', x: x as string, y: y as string, d: d as string }
}

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T
}

async function newAgent<Modules extends ModulesMap>(modules: Modules) {
  const dm = new DependencyManager()
  dm.registerInstance(InjectionSymbols.StorageService, new MemoryStorageService())
  const agent = new Agent(
    {
      // An empty in-memory store has no storage-version record; updating it migrates nothing.
      config: { logger: new ConsoleLogger(LogLevel.Warn), autoUpdateStorageOnStartup: true },
      dependencies: agentDependencies,
      modules: {
        kms: new Kms.KeyManagementModule({
          backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
        }),
        ...modules,
      },
    },
    dm
  )
  await agent.initialize()
  return agent
}

function issuerAgent() {
  return newAgent({
    cheqd: new CheqdModule({ networks: [{ network: 'testnet', rpcUrl: RPC, cosmosPayerSeed: LOCALNET_PAYER }] }),
    dids: new DidsModule({ registrars: [new CheqdDidRegistrar()], resolvers: [new CheqdDidResolver()] }),
  })
}

type IssuerAgent = Awaited<ReturnType<typeof issuerAgent>>

async function publishStatusList(agent: IssuerAgent, did: string, token: string, version: string) {
  const id = randomUUID()
  const result = await agent.modules.cheqd.createResource(did, {
    id,
    name: STATUS_LIST_NAME,
    resourceType: STATUS_LIST_TYPE,
    version,
    // The token's bytes, handed over as base64: createResource decodes a string as base64, and
    // it serialises any object, a Uint8Array included (typeof 'object'), as JSON.
    data: TypedArrayEncoder.toBase64(TypedArrayEncoder.fromUtf8String(token)),
  })
  if (result.resourceState.state !== 'finished') {
    throw new Error(`publishing the status list failed: ${result.resourceState.reason}`)
  }
  log(`status list version ${version} published as DID-Linked Resource ${did}/resources/${id}`)
  return id
}

async function issue(work: string) {
  const issuerKey = newP256()
  const holderKey = newP256()
  writeFileSync(path.join(work, 'issuer-key.json'), JSON.stringify(issuerKey))
  writeFileSync(path.join(work, 'holder-key.json'), JSON.stringify(holderKey))

  const agent = await issuerAgent()
  const { keyId } = await agent.kms.importKey({ privateJwk: { ...issuerKey } })

  const did = `did:cheqd:testnet:${randomUUID()}`
  const didUrl = `${did}#key-1`
  const didDocument = JsonTransformer.fromJSON(
    {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: didUrl,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk: { kty: 'EC', crv: 'P-256', x: issuerKey.x, y: issuerKey.y },
        },
      ],
      authentication: [didUrl],
      assertionMethod: [didUrl],
    },
    DidDocument
  )
  const created = await agent.dids.create({
    method: 'cheqd',
    didDocument,
    options: { keys: [{ kmsKeyId: keyId, didDocumentRelativeKeyId: '#key-1' }] },
  } as never)
  if (created.didState.state !== 'finished') {
    throw new Error(`registering ${did} failed: ${JSON.stringify(created.didState)}`)
  }
  log(`DID registered on the localnet: ${did} (verification method ${didUrl}, JsonWebKey2020, EC P-256)`)

  // The status list: 1024 entries of one bit, all VALID, signed by the DID's key, published as a
  // DID-Linked Resource. The credential names it by the DID URL that resolves to its latest version.
  const statusUri = `${did}?resourceName=${STATUS_LIST_NAME}&resourceType=${STATUS_LIST_TYPE}`
  const statusIndex = randomInt(1, 1024)
  const list = await agent.tokenStatusList.createTokenStatusList<'jwt'>({
    format: 'jwt',
    statusList: { statusListLength: 1024, bitsPerStatus: 1 },
    statusListUri: statusUri,
    signer: { method: 'did', didUrl },
    alg: 'ES256',
  })
  const v1 = await publishStatusList(agent, did, list.statusList, '1')

  const holderJwk = Kms.PublicJwk.fromPublicJwk({ kty: 'EC', crv: 'P-256', x: holderKey.x, y: holderKey.y })
  const credential = await agent.sdJwtVc.sign({
    issuer: { method: 'did', didUrl },
    holder: { method: 'jwk', jwk: holderJwk },
    payload: {
      vct: 'urn:eudi:pid:1',
      given_name: 'Erika',
      family_name: 'Mustermann',
      status: { status_list: { idx: statusIndex, uri: statusUri } },
    },
    disclosureFrame: { _sd: ['given_name', 'family_name'] },
  })
  log(`credential issued: typ=${credential.header.typ} alg=${credential.header.alg} kid=${credential.header.kid} iss=${credential.payload.iss} status idx ${statusIndex}`)

  const issued: Issued = {
    did,
    didUrl,
    statusUri,
    statusIndex,
    statusListToken: list.statusList,
    resources: [v1],
    credential: credential.compact,
  }
  writeFileSync(path.join(work, 'issued.json'), JSON.stringify(issued, null, 2))
  await agent.shutdown()
}

async function revoke(work: string) {
  const issued = readJson<Issued>(path.join(work, 'issued.json'))
  const issuerKey = readJson<PrivateJwk>(path.join(work, 'issuer-key.json'))
  const agent = await issuerAgent()
  const { keyId } = await agent.kms.importKey({ privateJwk: { ...issuerKey } })
  // A fresh process: Credo resolves the DID from the localnet and links the key to it again.
  await agent.dids.import({ did: issued.did, keys: [{ kmsKeyId: keyId, didDocumentRelativeKeyId: '#key-1' }] })
  const updated = await agent.tokenStatusList.updateTokenStatusList<'jwt'>({
    format: 'jwt',
    token: issued.statusListToken,
    status: { index: issued.statusIndex, status: 1 },
    signer: { method: 'did', didUrl: issued.didUrl },
    alg: 'ES256',
  })
  const v2 = await publishStatusList(agent, issued.did, updated.statusList, '2')
  log(`credential at index ${issued.statusIndex} revoked (status 1, INVALID) in version 2`)
  writeFileSync(
    path.join(work, 'issued.json'),
    JSON.stringify({ ...issued, statusListToken: updated.statusList, resources: [...issued.resources, v2] }, null, 2)
  )
  await agent.shutdown()
}

async function present(work: string, uri: string, anchorFile: string) {
  const issued = readJson<Issued>(path.join(work, 'issued.json'))
  const holderKey = readJson<PrivateJwk>(path.join(work, 'holder-key.json'))
  const agent = await newAgent({
    // The registration `polaris-oid4vp keygen` tells a counterparty to make: trust the CA.
    x509: new X509Module({ trustedCertificates: [readFileSync(anchorFile, 'utf8')] }),
    openid4vc: new OpenId4VcModule(),
    // The holder resolves the issuer's DID itself, on the localnet, with Credo's cheqd resolver.
    cheqd: new CheqdModule({ networks: [{ network: 'testnet', rpcUrl: RPC }] }),
    dids: new DidsModule({ resolvers: [new CheqdDidResolver()] }),
  })
  // The holder checks the credential before it keeps it: Credo resolves the issuer's DID on the
  // localnet and verifies the signature under the key the document names. Credo's status check
  // stays off: it fetches a status list uri over HTTP, and this one is a DID URL (README,
  // Observations). HOLDER_STATUS_CHECK=1 turns it on, to show that.
  const statusCheck = process.env.HOLDER_STATUS_CHECK === '1'
  const verified = await agent.sdJwtVc.verify({
    compactSdJwtVc: issued.credential,
    trustedIssuers: [{ method: 'did', issuance: issued.did }],
    disableStatusValidation: !statusCheck,
  })
  if (!verified.isValid) {
    console.log(`CREDENTIAL REFUSED: ${verified.error?.message}`)
    await agent.shutdown()
    return
  }
  log(`holder verified the credential: Credo resolved ${issued.did} on the localnet and checked the issuer's signature`)
  const { keyId } = await agent.kms.importKey({ privateJwk: { ...holderKey } })
  const record = new SdJwtVcRecord({ credentialInstances: [{ compactSdJwtVc: issued.credential, kmsKeyId: keyId }] })
  await agent.sdJwtVc.store({ record })
  log(`holder stored the credential (vct ${record.getTags().vct})`)

  let resolved: Awaited<ReturnType<typeof agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest>>
  try {
    resolved = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(uri)
  } catch (err) {
    console.log(`REQUEST REFUSED: ${(err as Error).message}`)
    await agent.shutdown()
    return
  }
  log(
    `request resolved: client_id prefix ${resolved.verifier.clientIdPrefix}, response_mode ` +
      `${resolved.authorizationRequestPayload.response_mode}, DCQL satisfied ${resolved.dcql?.queryResult.can_be_satisfied}`
  )
  if (!resolved.dcql?.queryResult.can_be_satisfied) {
    console.log('REQUEST REFUSED: the DCQL query cannot be satisfied from the store')
    await agent.shutdown()
    return
  }
  const credentials = agent.openid4vc.holder.selectCredentialsForDcqlRequest(resolved.dcql.queryResult)
  try {
    const accepted = await agent.openid4vc.holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolved.authorizationRequestPayload,
      dcql: { credentials },
    })
    const server = accepted.serverResponse as { status?: number; body?: unknown } | undefined
    console.log(
      `${accepted.ok ? 'DISPATCHED' : 'DISPATCH FAILED'}: the verifier answered ${server?.status} ${JSON.stringify(server?.body)}`
    )
  } catch (err) {
    console.log(`DISPATCH FAILED: ${(err as Error).message}`)
  }
  await agent.shutdown()
}

const [command, work, ...rest] = process.argv.slice(2)
const run =
  command === 'issue' && work
    ? issue(work)
    : command === 'revoke' && work
      ? revoke(work)
      : command === 'present' && work && rest.length === 2
        ? present(work, rest[0], rest[1])
        : Promise.reject(new Error('usage: walk.ts issue WORK | present WORK URI ANCHOR | revoke WORK'))
run.then(
  () => process.exit(0),
  (err) => {
    console.error(err)
    process.exit(1)
  }
)
