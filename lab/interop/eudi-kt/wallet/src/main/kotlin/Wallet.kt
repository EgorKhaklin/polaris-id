// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet built on the EU reference OpenID4VP library presents one SD-JWT VC to polaris-oid4vp.
// The library resolves the request (x509_hash, the signed request object fetched by POST) and
// dispatches the encrypted direct_post.jwt response; the presentation itself is the wallet's to
// build, as the library's own Example.kt builds it: the credential and a key binding JWT.
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.SignedRequestConfiguration
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.SupportedRequestUriMethods
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import kotlin.system.exitProcess

fun main(args: Array<String>): Unit = runBlocking {
    if (args.size != 4) {
        System.err.println("usage: wallet <openid4vp://...> <credential.txt> <holder-key.json> <anchor.pem>")
        exitProcess(2)
    }
    val (uri, credentialFile, holderKeyFile, anchorFile) = args
    val credential = File(credentialFile).readText().trim()
    val holderKey = ECKey.parse(File(holderKeyFile).readText())
    val anchor = CertificateFactory.getInstance("X.509")
        .generateCertificate(File(anchorFile).inputStream()) as X509Certificate

    // x509_hash: the request object is trusted when its x5c holds a certificate the anchor signed,
    // the registration polaris-oid4vp keygen asks a counterparty to make. Nothing is trusted blindly.
    val trust = X509CertificateTrust { chain ->
        chain.any { cert ->
            cert.issuerX500Principal == anchor.subjectX500Principal &&
                runCatching { cert.verify(anchor.publicKey); true }.getOrDefault(false)
        }
    }
    val config = OpenId4VPConfig(
        vpFormatsSupported = VpFormatsSupported(sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.ES256),
            supportedRequestUriMethods = SupportedRequestUriMethods.Both(SupportedRequestUriMethods.Post()),
        ),
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
            supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
            supportedMethods = listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM),
        ),
        supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509Hash(trust)),
    )
    val http = HttpClient(OkHttp) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        expectSuccess = true
    }
    http.use {
        val openId4Vp = OpenId4Vp.overRedirects(config, it)
        when (val resolution = openId4Vp.resolveRequestUri(uri)) {
            is Resolution.Invalid -> {
                println("REQUEST REFUSED by the wallet: ${resolution.error}")
                exitProcess(3)
            }
            is Resolution.Success -> {
                val request = resolution.requestObject
                val query = request.query.credentials.value.first()
                println("resolved   client=${request.client.id.clientId} query=${query.id.value} format=${query.format.value}")
                val presentation = present(credential, holderKey, request.client.id.clientId, request.nonce)
                val consensus = Consensus.PositiveConsensus(
                    VerifiablePresentations(mapOf(query.id to listOf(presentation))),
                )
                val outcome = runCatching {
                    openId4Vp.dispatch(request, consensus, EncryptionParameters.DiffieHellman(Base64URL.encode("polaris")))
                }
                outcome.onSuccess { println("DISPATCHED $it") }
                outcome.onFailure { println("DISPATCH FAILED $it"); exitProcess(4) }
            }
        }
    }
}

/** The SD-JWT VC as issued (ending in "~") and a key binding JWT over it, for this request. */
fun present(sdJwtVc: String, holderKey: ECKey, audience: String, nonce: String): VerifiablePresentation.Generic {
    val sdHash = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(sdJwtVc.toByteArray(Charsets.US_ASCII)))
    val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("kb+jwt")).build()
    val claims = JWTClaimsSet.Builder()
        .audience(audience)
        .claim("nonce", nonce)
        .issueTime(Date())
        .claim("sd_hash", sdHash)
        .build()
    val keyBinding = SignedJWT(header, claims).apply { sign(ECDSASigner(holderKey)) }
    return VerifiablePresentation.Generic(sdJwtVc + keyBinding.serialize())
}
