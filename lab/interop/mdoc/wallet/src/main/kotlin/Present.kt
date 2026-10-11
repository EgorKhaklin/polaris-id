// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// An mso_mdoc presentation over OpenID4VP 1.0 direct_post.jwt, written to a capture directory
// before it is sent. It replaces ../../eudi-issuer/wallet's Present.kt; Issue.kt and Main.kt are
// that wallet's (capture.sh copies them, with the mso_mdoc configuration id it asks for).
//
// - eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt resolves the request (x509_hash, the signed request
//   object fetched by POST, the DCQL query) and dispatches the encrypted response.
// - id.walt.mdoc-credentials:waltid-mdoc-credentials-jvm, the mdoc library the EU reference
//   verifier endpoint builds on, selects the issuer-signed items and signs DeviceAuthentication.
// - The SessionTranscript is the wallet's (neither library builds one): OpenID4VP 1.0 B.2.6.1, as the EUDI iOS wallet
//   kit 0.54.5 builds it (Openid4VpUtils.generateOpenId4VpHandover), with the RFC 7638 SHA-256
//   thumbprint of the key the library encrypts the response to.
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import COSE.AlgorithmID
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SignedRequestConfiguration
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.SupportedRequestUriMethods
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.ByteStringElement
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.NullElement
import id.walt.mdoc.dataelement.StringElement
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.docrequest.MDocRequestBuilder
import id.walt.mdoc.issuersigned.IssuerSigned
import id.walt.mdoc.mdocauth.DeviceAuthentication
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.system.exitProcess

suspend fun present(args: List<String>) {
    if (args.size != 5) {
        System.err.println("usage: wallet present <openid4vp://...> <issuer-signed.b64url> <holder-key.json> <anchor.pem> <capture-dir>")
        exitProcess(2)
    }
    val (uri, credentialFile, holderKeyFile, anchorFile, captureDir) = args
    val issuerSignedBytes = Base64.getUrlDecoder().decode(File(credentialFile).readText().trim())
    require(issuerSignedBytes.isNotEmpty()) { "empty credential" }
    val holderKey = ECKey.parse(File(holderKeyFile).readText())
    val anchor = CertificateFactory.getInstance("X.509")
        .generateCertificate(File(anchorFile).inputStream()) as X509Certificate

    val trust = X509CertificateTrust { chain ->
        chain.any { cert ->
            cert.issuerX500Principal == anchor.subjectX500Principal &&
                runCatching { cert.verify(anchor.publicKey); true }.getOrDefault(false)
        }
    }
    val config = OpenId4VPConfig(
        vpFormatsSupported = VpFormatsSupported(
            sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP,
            msoMdoc = VpFormatsSupported.MsoMdoc(),
        ),
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
        val request = when (val resolution = openId4Vp.resolveRequestUri(uri)) {
            is Resolution.Invalid -> {
                println("REQUEST REFUSED by the wallet: ${resolution.error}")
                exitProcess(3)
            }
            is Resolution.Success -> resolution.requestObject
        }
        val query = request.query.credentials.value.first()
        // An mso_mdoc query names [namespace, element]; an SD-JWT VC query names [claim].
        val paths = query.claims?.map { claim -> claim.path.value.mapNotNull { e -> (e as? ClaimPathElement.Claim)?.name } }
        val wanted = paths?.mapNotNull { p -> p.lastOrNull() }
        val queriedNamespace = paths?.firstOrNull { p -> p.size == 2 }?.first()
        require(!wanted.isNullOrEmpty()) { "the query names no claims" }
        val clientId = request.client.id.clientId
        val (responseMode, responseUri) = when (val m = request.responseMode) {
            is ResponseMode.DirectPostJwt -> "direct_post.jwt" to m.responseURI.toString()
            is ResponseMode.DirectPost -> "direct_post" to m.responseURI.toString()
            else -> error("not direct_post(.jwt): $m")
        }
        // B.2.6.1: the thumbprint of the key the response is encrypted to; null when it is not.
        val encKey = request.responseEncryptionSpecification?.recipientKey
        require((encKey != null) == (responseMode == "direct_post.jwt")) { "$responseMode with encryption key $encKey" }
        val thumbprint = encKey?.computeThumbprint("SHA-256")?.decode()
        println("resolved   client=$clientId mode=$responseMode query=${query.id.value} format=${query.format.value} claims=$wanted")

        checkSpecVector()
        val transcript = sessionTranscript(clientId, request.nonce, thumbprint, responseUri)

        // walt.id's mdoc: the issued IssuerSigned, the items the query names, and the device
        // signature over DeviceAuthentication with empty device namespaces.
        val issued = IssuerSigned.fromMapElement(EncodedCBORElement(issuerSignedBytes).decodeDataElement<MapElement>())
        val docType = issued.issuerAuth?.payload?.let { p ->
            (EncodedCBORElement.fromEncodedCBORElementData(p).decode() as MapElement)
                .value.entries.first { e -> e.key.str == "docType" }.value.let { v -> (v as StringElement).value }
        } ?: error("no MSO")
        val mdoc = MDoc(StringElement(docType), issued, null)
        val namespace = queriedNamespace ?: mdoc.nameSpaces.first()
        val mdocRequest = wanted.fold(MDocRequestBuilder(docType)) { b, name -> b.addDataElementRequest(namespace, name, false) }.build()
        val deviceAuthentication = DeviceAuthentication(transcript, docType, EncodedCBORElement(MapElement(mapOf())))
        val crypto = SimpleCOSECryptoProvider(listOf(
            COSECryptoProviderKeyInfo("device", AlgorithmID.ECDSA_256, holderKey.toECPublicKey(), holderKey.toECPrivateKey()),
        ))
        val presented = mdoc.presentWithDeviceSignature(mdocRequest, deviceAuthentication, crypto, "device")
        val deviceResponse = DeviceResponse(listOf(presented)).toCBOR()
        println("built      DeviceResponse ${deviceResponse.size} bytes, docType $docType, namespace $namespace, items $wanted")

        val out = File(captureDir).apply { mkdirs() }
        File(out, "device-response.cbor").writeBytes(deviceResponse)
        File(out, "openid4vp-inputs.json").writeText(buildJsonObject {
            put("client_id", clientId)
            put("response_uri", responseUri)
            put("nonce", request.nonce)
            put("response_mode", responseMode)
            put("jwk_thumbprint", thumbprint?.let { t -> JsonPrimitive(Base64URL.encode(t).toString()) } ?: JsonNull)
            put("encryption_jwk", encKey?.let { k -> Json.parseToJsonElement(k.toPublicJWK().toJSONString()) } ?: JsonNull)
            put("wallet_session_transcript_hex", transcript.toCBOR().joinToString("") { b -> "%02x".format(b) })
            put("dcql_query_id", query.id.value)
            put("dcql_query_format", query.format.value)
            put("state", request.state?.let { s -> JsonPrimitive(s) } ?: JsonNull)
        }.toString())
        println("CAPTURED   $captureDir")

        val consensus = Consensus.PositiveConsensus(VerifiablePresentations(mapOf(
            query.id to listOf(VerifiablePresentation.Generic(Base64URL.encode(deviceResponse).toString())),
        )))
        val outcome = runCatching {
            openId4Vp.dispatch(request, consensus, EncryptionParameters.DiffieHellman(Base64URL.encode("polaris")))
        }
        outcome.onSuccess { result -> println("DISPATCHED $result") }
        outcome.onFailure { error -> println("DISPATCH FAILED $error") }
    }
}

/**
 * OpenID4VP 1.0 B.2.6.1: SessionTranscript = [null, null, ["OpenID4VPHandover",
 * sha256(cbor([client_id, nonce, jwk_thumbprint, response_uri]))]]
 */
fun sessionTranscript(clientId: String, nonce: String, thumbprint: ByteArray?, responseUri: String): ListElement {
    val handoverInfo = ListElement(listOf(
        StringElement(clientId), StringElement(nonce), thumbprint?.let { t -> ByteStringElement(t) } ?: NullElement(),
        StringElement(responseUri),
    )).toCBOR()
    return ListElement(listOf(
        NullElement(), NullElement(),
        ListElement(listOf(StringElement("OpenID4VPHandover"),
            ByteStringElement(MessageDigest.getInstance("SHA-256").digest(handoverInfo)))),
    ))
}

/**
 * The construction above, run on the non-normative example of OpenID4VP 1.0 B.2.6.1 (its JWK,
 * client_id, nonce and response_uri), must give the example's SessionTranscript byte for byte;
 * otherwise the wallet stops before it signs anything. The same vector pins verify_mdoc.py.
 */
fun checkSpecVector() {
    val jwk = ECKey.parse(
        """{"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",""" +
            """"y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"ECDH-ES","kid":"1"}""",
    )
    val got = sessionTranscript(
        "x509_san_dns:example.com", "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
        jwk.computeThumbprint("SHA-256").decode(), "https://example.com/response",
    ).toCBOR().joinToString("") { b -> "%02x".format(b) }
    val spec = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e" +
        "ed494cefdd9d95240d254b046b11b68013722aad38ac"
    check(got == spec) { "SessionTranscript construction does not reproduce the OpenID4VP 1.0 B.2.6.1 example: $got" }
    println("spec       the SessionTranscript construction reproduces the OpenID4VP 1.0 B.2.6.1 example")
}
