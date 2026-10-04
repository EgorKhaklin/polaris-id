// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on Multipaz presents one SD-JWT VC to polaris-oid4vp over OpenID4VP 1.0.
//
//   polaris-multipaz-wallet <openid4vp://...> <credential.txt> <holder-key.json> <anchor.pem>
//
// Multipaz's uriSchemePresentment() does the protocol: it fetches the signed request object (by
// POST when the launch URI says so), checks its signature against the x5c leaf, asks the
// presentment source whom it trusts, matches the DCQL query against the document store, builds the
// presentation (the disclosures and a key binding JWT signed in its software secure area) and posts
// the response, encrypted to the verifier's key (ECDH-ES). This file wires what a wallet app wires:
// the holder key and the credential, the anchor its trust manager holds, and the consent step.
import io.ktor.client.engine.java.Java
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.presentment.PresentmentCanceledException
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.presentment.uriSchemePresentment
import org.multipaz.prompt.promptModelSilentConsent
import org.multipaz.request.TrustedRequesterIdentity
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.trustmanagement.ConfigurableTrustManager
import org.multipaz.trustmanagement.TrustEntryX509Cert
import org.multipaz.trustmanagement.TrustMetadata
import java.io.File
import kotlin.system.exitProcess

private const val DOMAIN = "sdjwt"

fun main(args: Array<String>) = runBlocking {
    if (args.size != 4) {
        System.err.println("usage: polaris-multipaz-wallet <openid4vp://...> <credential.txt> <holder-key.json> <anchor.pem>")
        exitProcess(2)
    }
    val (launchUri, credentialFile, holderKeyFile, anchorFile) = args

    // The holder key goes into Multipaz's software secure area; the credential, bound to it, is
    // stored as the issuer sent it.
    val storage = EphemeralStorage()
    val secureArea = SoftwareSecureArea.create(storage)
    val documentStore = buildDocumentStore(storage, SecureAreaRepository.Builder().add(secureArea).build()) {}
    val holderKey = EcPrivateKey.fromJwk(Json.parseToJsonElement(File(holderKeyFile).readText()).jsonObject)
    KeyBoundSdJwtVcCredential.create(
        document = documentStore.createDocument(displayName = "PID"),
        asReplacementForIdentifier = null,
        domain = DOMAIN,
        secureArea = secureArea,
        vct = "urn:eudi:pid:1",
        createKeySettings = SoftwareCreateKeySettings.Builder().setPrivateKey(holderKey).build(),
    ).certify(File(credentialFile).readText().trim().encodeToByteString())

    // The verifiers the wallet trusts: one CA, in Multipaz's trust manager.
    val anchor = X509Cert.fromPem(File(anchorFile).readText())
    val trustManager = ConfigurableTrustManager(
        identifier = "verifiers",
        entries = listOf(TrustEntryX509Cert("anchor", TrustMetadata(displayName = "test verifier CA", testOnly = true), anchor)),
    )

    var stage = "fetching the request"
    val source = SimplePresentmentSource(
        documentStore = documentStore,
        documentTypeRepository = DocumentTypeRepository(),
        resolveTrustFn = { requester ->
            stage = "resolving trust"
            requester.requesterIdentities.firstNotNullOfOrNull { identity ->
                val verdict = trustManager.verify(identity.certChain.certificates)
                println("TRUST " + if (verdict.isTrusted) "trusted" else "not trusted: ${verdict.error?.message}")
                if (verdict.isTrusted) TrustedRequesterIdentity(identity, verdict.trustPoints.first().metadata) else null
            }
        },
        // Multipaz hands the consent step its trust verdict; a wallet app shows it to the user in a
        // prompt. This wallet has no user: it consents to a trusted verifier and declines any other.
        showConsentPromptFn = { requester, trusted, consentData, preselected, onFocus ->
            if (trusted == null) {
                null
            } else {
                stage = "presenting"
                promptModelSilentConsent(requester, trusted, consentData, preselected, onFocus)
            }
        },
        domainsKeyBoundSdJwt = listOf(DOMAIN),
    )

    try {
        val redirect = uriSchemePresentment(source, launchUri, appId = null, origin = null, httpClientEngineFactory = Java)
        println("DISPATCHED the verifier answered 200, redirect_uri $redirect")
    } catch (e: PresentmentCanceledException) {
        println("REQUEST REFUSED the verifier is not trusted, nothing was sent (${e::class.simpleName}: ${e.message})")
        exitProcess(1)
    } catch (e: Exception) {
        val outcome = if (stage == "presenting") "DISPATCH FAILED" else "REQUEST REFUSED"
        println("$outcome while $stage: ${e::class.simpleName}: ${e.message}")
        exitProcess(1)
    }
}
