// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on vck (A-SIT Plus) presents one SD-JWT VC to polaris-oid4vp, and vck issued it.
//
//   wallet issue   <issuer-key.pem> <issuer-kid> <holder-key.pem> <credential.txt>
//   wallet present <openid4vp://...> <credential.txt> <holder-key.pem> <anchor.pem>
//
// `issue` has vck's IssuerAgent sign the credential, bound to the holder's key. `present` has vck's
// OpenID4VP wallet resolve the request (x509_hash, the signed request object fetched by POST with
// wallet metadata and a wallet nonce), build the presentation (the disclosures and the key binding
// JWT) and dispatch the encrypted direct_post.jwt response. This file only wires the keys, the
// stored credential and the anchor the wallet trusts for the verifier.
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.SignerBasedKeyMaterial
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.ktor.openid.OpenId4VpWallet
import at.asitplus.wallet.lib.openid.RelyingPartyTrust
import io.ktor.client.engine.cio.CIO
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.system.exitProcess
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/** The EU PID type polaris-oid4vp asks for by default. */
object Pid : SdJwtCredentialScheme {
    override val sdJwtType = "urn:eudi:pid:1"
}

fun signer(pemFile: String): Signer {
    val key = CryptoPrivateKey.decodeFromPem(File(pemFile).readText()).getOrThrow()
    require(key is CryptoPrivateKey.EC.WithPublicKey) { "$pemFile is not an EC private key" }
    return SignatureAlgorithm.ECDSAwithSHA256.signerFor(key).getOrThrow()
}

/** The holder's key, carried in the credential's cnf. */
class HolderKey(signer: Signer) : SignerBasedKeyMaterial(signer) {
    override suspend fun getCertificate(): X509Certificate? = null
}

/** The issuer's key. vck puts its public JWK in the credential's header, which is how vck's holder
 *  checks the signature before storing it; polaris-oid4vp ignores that header and trusts only the
 *  keys it was configured with (--issuer-jwks). */
class IssuerKey(signer: Signer, kid: String) : SignerBasedKeyMaterial(signer, kid) {
    override suspend fun getCertificate(): X509Certificate? = null
}

suspend fun issue(issuerPem: String, kid: String, holderPem: String, out: String) {
    val holder = HolderKey(signer(holderPem))
    val issuer = IssuerAgent(
        keyMaterial = IssuerKey(signer(issuerPem), kid),
        identifier = "https://issuer.vck.example".toUri(),
    )
    val issued = issuer.issueCredential(
        CredentialToBeIssued.VcSd(
            claims = listOf(ClaimToBeIssued("given_name", "Erika"), ClaimToBeIssued("family_name", "Mustermann")),
            expiration = Clock.System.now() + 30.days,
            scheme = Pid,
            subjectPublicKey = holder.publicKey,
            userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
        )
    ).getOrThrow() as Issuer.IssuedCredential.VcSdJwt
    File(out).writeText(issued.signedSdJwtVc.serialize())
    println("ISSUED by vck's IssuerAgent")
}

suspend fun present(uri: String, credentialFile: String, holderPem: String, anchorPem: String) {
    val holderKey = HolderKey(signer(holderPem))
    val holder = HolderAgent(holderKey)
    val vcSdJwt = File(credentialFile).readText().trim()
    holder.storeCredential(
        Holder.StoreCredentialInput.SdJwt(SdJwtSigned.parseCatching(vcSdJwt).getOrThrow(), vcSdJwt, Pid)
    ).getOrThrow()
    // x509_hash: the request object is trusted when its x5c chains to this anchor, the registration
    // polaris-oid4vp keygen asks a counterparty to make. Nothing is trusted blindly.
    val anchor = X509Certificate.decodeFromPem(File(anchorPem).readText()).getOrThrow()
    val wallet = OpenId4VpWallet(
        engine = CIO.create(),
        keyMaterial = holderKey,
        holderAgent = holder,
        relyingPartyTrust = setOf(RelyingPartyTrust.Certificates(TrustedCertificates { setOf(anchor) })),
    )
    val state = wallet.startAuthorizationResponsePreparation(uri).getOrElse {
        println("REQUEST REFUSED ${it::class.simpleName}: ${it.message}")
        return
    }
    val result = wallet.finalizeAuthorizationResponse(state).getOrElse {
        println("DISPATCH FAILED ${it::class.simpleName}: ${it.message}")
        return
    }
    println("DISPATCHED $result")
}

fun main(args: Array<String>): Unit = runBlocking {
    when {
        args.size == 5 && args[0] == "issue" -> issue(args[1], args[2], args[3], args[4])
        args.size == 5 && args[0] == "present" -> present(args[1], args[2], args[3], args[4])
        else -> {
            System.err.println("usage: wallet issue <issuer-key.pem> <kid> <holder-key.pem> <out>\n" +
                "       wallet present <openid4vp://...> <credential.txt> <holder-key.pem> <anchor.pem>")
            exitProcess(2)
        }
    }
}
