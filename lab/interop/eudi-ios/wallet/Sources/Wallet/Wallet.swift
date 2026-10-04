// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet built on the EU reference OpenID4VP library for iOS presents one SD-JWT VC to
// polaris-oid4vp. The library resolves the request (x509_hash, the signed request object fetched by
// POST) and dispatches the encrypted direct_post.jwt response. The presentation is the wallet's to
// build, and it is built with the EU SD-JWT library the way the EUDI iOS wallet kit builds one: the
// disclosures the DCQL query names, and a key binding JWT over them.
import CryptoKit
import Foundation
import JSONWebAlgorithms
import JSONWebSignature
import OpenID4VP
import Security
import SwiftyJSON
import eudi_lib_sdjwt_swift
// Both EU libraries name a ClaimPath and a Networking, and the OpenID4VP module's main class shares
// the module's name, so these two are imported by kind, as the EUDI iOS wallet kit imports them.
import struct OpenID4VP.ClaimPath
import protocol OpenID4VP.Networking

@main
struct Wallet {
  static func main() async {
    setvbuf(stdout, nil, _IOLBF, 0)
    let args = CommandLine.arguments
    guard args.count == 6, let uri = URL(string: args[1]) else {
      FileHandle.standardError.write(Data(
        "usage: wallet <openid4vp://...> <credential.txt> <holder-key.json> <anchor.pem> <tls.pem>\n".utf8))
      exit(2)
    }
    let credential: String
    let holderKey: P256.Signing.PrivateKey
    let anchor: SecCertificate
    let listener: Data
    do {
      credential = try String(contentsOfFile: args[2], encoding: .ascii)
        .trimmingCharacters(in: .whitespacesAndNewlines)
      holderKey = try loadPrivateKey(jwkFile: args[3])
      anchor = try loadCertificate(pemFile: args[4])
      listener = SecCertificateCopyData(try loadCertificate(pemFile: args[5])) as Data
    } catch {
      FileHandle.standardError.write(Data("cannot read the inputs: \(error)\n".utf8))
      exit(2)
    }

    // x509_hash: the request object is trusted when its x5c chains to the anchor polaris-oid4vp keygen
    // made, the registration it asks a counterparty to make. Nothing is trusted blindly.
    let trust: CertificateTrust = { x5c in chainsTo(anchor, x5c) }
    // The listener's self-signed certificate is pinned for this session only; nothing else changes.
    let session = URLSession(
      configuration: .ephemeral, delegate: PinnedListener(pinned: listener), delegateQueue: nil)
    let http = LoggedSession(session: session)
    let config: OpenId4VPConfiguration
    do {
      config = OpenId4VPConfiguration(
        privateKey: try KeyController.generateECDHPrivateKey(),
        publicWebKeySet: WebKeySet(keys: []),
        supportedClientIdSchemes: [.x509Hash(trust: trust)],
        jarConfiguration: .noEncryptionOption,
        vpConfiguration: VPConfiguration(
          vpFormatsSupported: try VpFormatsSupported(values: [
            .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
          ]),
          supportedTransactionDataTypes: []),
        session: http,
        responseEncryptionConfiguration: .supported(
          supportedAlgorithms: [.init(.ECDH_ES)], supportedMethods: [.init(.A128GCM), .init(.A256GCM)])
      )
    } catch {
      FileHandle.standardError.write(Data("cannot configure the library: \(error)\n".utf8))
      exit(2)
    }

    let openId4Vp = OpenID4VP(walletConfiguration: config)
    let resolved: ResolvedRequestData
    switch await openId4Vp.authorize(
      fetcher: Fetcher<String>(session: http), poster: Poster(session: http), url: uri)
    {
    case .invalidResolution(let error, _):
      print("REQUEST REFUSED by the wallet: \(error)")
      exit(3)
    case .notSecured:
      print("REQUEST REFUSED by the wallet: the request is not signed")
      exit(3)
    case .jwt(let request, _):
      resolved = request
    }
    let request = resolved.request
    guard let query = resolved.dcql?.credentials.first else {
      print("REQUEST REFUSED by the wallet: no DCQL credential query")
      exit(3)
    }
    let clientId = request.client.id.clientId
    print("resolved   client=\(clientId) query=\(query.id.value) format=\(query.format.format)")

    do {
      let presentation = try await present(
        credential, holderKey: holderKey, query: query, audience: clientId, nonce: request.nonce)
      let consent = ClientConsent.vpToken(
        vpContent: .dcql(verifiablePresentations: [query.id: [.generic(presentation)]]))
      let response = try AuthorizationResponse(
        resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: config,
        encryptionParameters: .apu(base64url(Data("polaris".utf8))))
      switch try await openId4Vp.dispatch(response: response) {
      case .accepted:
        print("DISPATCHED Accepted")
      case .rejected:
        print("DISPATCHED Rejected")
        exit(5)
      }
    } catch {
      print("DISPATCH FAILED \(error)")
      exit(4)
    }
  }
}

/// The SD-JWT VC as issued, cut to the disclosures the query names, with a key binding JWT (`aud`,
/// `nonce`, `iat`, `sd_hash`) signed by the holder key, as the EUDI iOS wallet kit presents one.
func present(
  _ credential: String, holderKey: P256.Signing.PrivateKey, query: CredentialQuery,
  audience: String, nonce: String
) async throws -> String {
  let issued = try CompactParser().getSignedSdJwt(serialisedString: credential)
  let requested = Set((query.claims ?? []).map { sdJwtPath($0.path) })
  guard let selected = try issued.present(query: requested) else {
    throw WalletError("the credential has nothing the query asks for")
  }
  let algorithm = HashingAlgorithmIdentifier(rawValue: issued.claimSet["_sd_alg"].string ?? "sha-256")
  guard let algorithm,
    let sdHash = DigestCreator(hashingAlgorithm: algorithm.hashingAlgorithm())
      .hashAndBase64Encode(input: CompactSerialiser(signedSDJWT: selected).serialised)
  else { throw WalletError("cannot compute sd_hash") }
  let payload: [String: Any] = [
    "aud": audience, "nonce": nonce, "iat": Int(Date().timeIntervalSince1970), "sd_hash": sdHash,
  ]
  let keyBinding = try KBJWT(
    header: DefaultJWSHeaderImpl(algorithm: .ES256), kbJwtPayload: JSON(payload))
  let presented = try await SDJWTIssuer.presentation(
    holdersPrivateKey: holderKey, signedSDJWT: selected,
    disclosuresToPresent: selected.disclosures, keyBindingJWT: keyBinding)
  guard presented.kbJwt != nil else { throw WalletError("the key binding JWT was not signed") }
  return presented.serialisation
}

/// A DCQL claim path, as the SD-JWT library spells the same path.
func sdJwtPath(_ path: ClaimPath) -> eudi_lib_sdjwt_swift.ClaimPath {
  eudi_lib_sdjwt_swift.ClaimPath(path.value.map { element in
    switch element {
    case .claim(let name): .claim(name: name)
    case .arrayElement(let index): .arrayElement(index: index)
    case .allArrayElements: .allArrayElements
    }
  })
}

/// True when the x5c chain (base64 DER, leaf first) verifies up to `anchor` and to nothing else.
func chainsTo(_ anchor: SecCertificate, _ x5c: [String]) -> Bool {
  let certificates = x5c.compactMap { Data(base64Encoded: $0) }
    .compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
  guard !certificates.isEmpty, certificates.count == x5c.count else { return false }
  var trust: SecTrust?
  guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust)
    == errSecSuccess, let trust
  else { return false }
  SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
  SecTrustSetAnchorCertificatesOnly(trust, true)
  SecTrustSetNetworkFetchAllowed(trust, false)
  return SecTrustEvaluateWithError(trust, nil)
}

/// Accepts the verifier's listener only when it presents exactly the pinned certificate (and the TLS
/// handshake has shown it holds that certificate's key). The system's TLS server policy is not the
/// test here: it refuses keygen's self-signed certificate, which names no extended key usage, so the
/// pin is checked as an X.509 certificate (its signature and validity), with itself as the only anchor.
final class PinnedListener: NSObject, URLSessionDelegate {
  let pinned: Data

  init(pinned: Data) { self.pinned = pinned }

  func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async
    -> (URLSession.AuthChallengeDisposition, URLCredential?)
  {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      let trust = challenge.protectionSpace.serverTrust
    else { return (.performDefaultHandling, nil) }
    let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
    guard let leaf = chain.first, SecCertificateCopyData(leaf) as Data == pinned,
      let anchor = SecCertificateCreateWithData(nil, pinned as CFData)
    else {
      print("tls        the listener did not present the pinned certificate")
      return (.cancelAuthenticationChallenge, nil)
    }
    SecTrustSetPolicies(trust, SecPolicyCreateBasicX509())
    SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
    SecTrustSetAnchorCertificatesOnly(trust, true)
    SecTrustSetNetworkFetchAllowed(trust, false)
    var error: CFError?
    guard SecTrustEvaluateWithError(trust, &error) else {
      print("tls        the pinned certificate failed evaluation: \(String(describing: error))")
      return (.cancelAuthenticationChallenge, nil)
    }
    return (.useCredential, URLCredential(trust: trust))
  }
}

/// The library's HTTP, through the pinned session, with one line per exchange for the log.
struct LoggedSession: Networking {
  let session: URLSession

  func data(from url: URL) async throws -> (Data, URLResponse) {
    try await data(for: URLRequest(url: url))
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    let line = "http       \(request.httpMethod ?? "GET") \(request.url?.path ?? "")"
    do {
      let (data, response) = try await session.data(for: request)
      print("\(line) <- \((response as? HTTPURLResponse)?.statusCode ?? 0)")
      return (data, response)
    } catch {
      print("\(line) failed: \(error.localizedDescription)")
      throw error
    }
  }
}

struct WalletError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

func loadCertificate(pemFile: String) throws -> SecCertificate {
  let body = try String(contentsOfFile: pemFile, encoding: .ascii)
    .split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
  guard let der = Data(base64Encoded: body),
    let certificate = SecCertificateCreateWithData(nil, der as CFData)
  else { throw WalletError("\(pemFile) is not a PEM certificate") }
  return certificate
}

func loadPrivateKey(jwkFile: String) throws -> P256.Signing.PrivateKey {
  let jwk = try JSON(data: Data(contentsOf: URL(fileURLWithPath: jwkFile)))
  guard jwk["kty"].string == "EC", jwk["crv"].string == "P-256",
    let d = jwk["d"].string.flatMap(base64urlDecode)
  else { throw WalletError("\(jwkFile) is not a P-256 private JWK") }
  return try P256.Signing.PrivateKey(rawRepresentation: d)
}

func base64url(_ data: Data) -> String {
  data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func base64urlDecode(_ text: String) -> Data? {
  var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
  return Data(base64Encoded: base64)
}
