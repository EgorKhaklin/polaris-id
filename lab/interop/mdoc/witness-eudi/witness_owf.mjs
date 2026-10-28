// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// @owf/mdoc 0.8.3 (OpenWallet Foundation identity-common-ts, Apache-2.0) as an mdoc witness:
// Verifier.verifyDeviceResponse over each case, with every check it reports.
//
//   node /deps/witness_owf.mjs /in/jobs.json
//
// The SessionTranscript is the library's own SessionTranscript.forOid4Vp(clientId, nonce,
// jwkThumbprint, responseUri), its bytes are reported, and the device signature is checked
// against it. The RFC 7638 thumbprint is jose's calculateJwkThumbprint.
//
// The MdocContext (the library's pluggable crypto, X.509 and fetch) is the upstream test context,
// packages/mdoc/src/__tests__/context.ts at identity-common-ts 0666f743 (the mdoc-v0.8.2 tag),
// ported from TypeScript: ECDSA by @noble/curves p256, chains by @peculiar/x509, public keys by
// jose. Its HKDF, HPKE and MAC entries are left out: DeviceMac is out of scope and refuses. fetch
// always throws: the run is offline. Nothing here is walt.id's or Polaris's verifier code.
// One JSON line per case, prefixed "WITNESS ", on stdout.
import 'reflect-metadata'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { p256 } from '@noble/curves/nist.js'
import { coseKeyToJwkClaim } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { CoseKey, SessionTranscript, Verifier } from '@owf/mdoc'
import * as x509 from '@peculiar/x509'
import { X509Certificate } from '@peculiar/x509'
import { calculateJwkThumbprint, exportJWK, importX509 } from 'jose'

const unsupported = (what) => async () => {
  throw new Error(`${what} is out of scope for this witness`)
}

const mdocContext = {
  fetch: async () => {
    throw new Error('offline: no fetch')
  },
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => new Uint8Array(await crypto.subtle.digest(digestAlgorithm, bytes)),
    random: (length) => crypto.getRandomValues(new Uint8Array(length)),
    hdkf: unsupported('HKDF'),
  },
  cose: {
    mac0: { authenticate: unsupported('COSE_Mac0'), verify: unsupported('COSE_Mac0') },
    sign1: {
      sign: unsupported('signing'),
      verify: async ({ signature, key, toBeVerified }) =>
        p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, { lowS: false }),
    },
  },
  x509: {
    getSubjectNameField: ({ certificate, field }) => new X509Certificate(certificate).subjectName.getField(field),
    getPublicKey: async ({ certificate, algorithm }) => {
      const cert = new X509Certificate(certificate)
      const key = await importX509(cert.toString(), coseKeyToJwkClaim.algorithm(algorithm), { extractable: true })
      return CoseKey.fromJwk(await exportJWK(key))
    },
    verifyCertificateChain: async ({ trustedCertificates, x5chain: certificateChain }) => {
      if (certificateChain.length === 0) throw new Error('Certificate chain is empty')
      const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0])
      const certificatesToBuildChain = [...certificateChain, ...(trustedCertificates ?? [])].map(
        (c) => new x509.X509Certificate(c)
      )
      const chain = await new x509.X509ChainBuilder({ certificates: certificatesToBuildChain }).build(parsedLeafCertificate)
      let parsedChain = chain.reverse()
      if (parsedChain.length < certificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
      }
      let previousCertificate
      if (trustedCertificates) {
        const parsedTrusted = trustedCertificates.map((t) => new X509Certificate(t))
        const index = parsedChain.findIndex((cert) => parsedTrusted.some((t) => cert.equal(t)))
        if (index === -1) throw new Error('No trusted certificate was found while validating the X.509 chain')
        if (index > 0) {
          previousCertificate = parsedChain[index - 1]
          parsedChain = parsedChain.slice(index)
        }
      }
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i]
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined
        const skipSignatureVerification = i === 0 && trustedCertificates && !publicKey
        if (!skipSignatureVerification) await cert.verify({ publicKey })
        previousCertificate = cert
      }
      return { chain: parsedChain.map((cert) => new Uint8Array(cert.rawData)) }
    },
    getCertificateData: async ({ certificate }) => {
      const cert = new X509Certificate(certificate)
      const thumbprint = await cert.getThumbprint(crypto)
      return {
        issuerName: cert.issuerName.toString(),
        subjectName: cert.subjectName.toString(),
        pem: cert.toString(),
        serialNumber: cert.serialNumber,
        thumbprint: hex.encode(new Uint8Array(thumbprint)),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
      }
    },
  },
}

const pemToDer = (text) =>
  [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map(
    (m) => new Uint8Array(Buffer.from(m[1].replace(/\s+/g, ''), 'base64'))
  )

const toHex = (bytes) => Buffer.from(bytes).toString('hex')

async function runCase(job) {
  const roots = job.roots.flatMap((p) => pemToDer(readFileSync(p, 'utf8')))
  const out = { name: job.name, at: job.at, roots: roots.length, checks: [] }
  try {
    const h = job.handover
    const jwkThumbprint = h.jwk ? new Uint8Array(Buffer.from(await calculateJwkThumbprint(h.jwk, 'sha256'), 'base64url')) : undefined
    const sessionTranscript = await SessionTranscript.forOid4Vp(
      { clientId: h.client_id, nonce: h.nonce, jwkThumbprint, responseUri: h.response_uri },
      mdocContext
    )
    out.transcript_hex = toHex(sessionTranscript.encode())
    await Verifier.verifyDeviceResponse(
      {
        deviceResponse: new Uint8Array(readFileSync(job.response)),
        sessionTranscript,
        trustedCertificates: roots.length ? [{ issuance: roots }] : [],
        now: new Date(job.at),
        onCheck: (c) => out.checks.push({ category: c.category, check: c.check, status: c.status, reason: c.reason }),
      },
      mdocContext
    )
    out.outcome = out.checks.some((c) => c.status === 'FAILED') ? 'refused' : 'accepted'
  } catch (e) {
    out.outcome = 'exception'
    out.exception = `${e?.name}: ${e?.message}`.slice(0, 300)
  }
  return out
}

const jobs = JSON.parse(readFileSync(process.argv[2], 'utf8'))
if (!jobs.length) throw new Error('no cases')
for (const job of jobs) console.log(`WITNESS ${JSON.stringify(await runCase(job))}`)
console.log(`WITNESS-DONE ${jobs.length}`)
