// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// The EU reference verifier (eudi-srv-verifier-endpoint v0.12.0) as a witness for the stages its
// own code decides, run in-process in its published image over a list of cases:
//
//   java -cp /workspace/BOOT-INF/classes:/workspace/BOOT-INF/lib/*:/driver WitnessKt /in/jobs.json
//
// Its mdoc decoding, MSO signature, value digests and device signature are walt.id's
// (waltid-mdoc-credentials 0.11.0, the library that built the captures), so they are reported
// but never counted. What is counted, each from the verifier's own code:
//   transcript  the SessionTranscript bytes its private toHandover() and SessionTranscript build
//               from (client_id, nonce, encryption JWK or null, response_uri), dumped, not inferred
//               from a signature check (DocumentValidator.kt toHandover, SessionTranscript);
//   trust       its IsChainTrustedForAttestation.msoMdocIssuance(chain, docType) over the
//               usingTrustAnchors(roots) PKIX check (revocation off), with the develop profile's
//               attestation classifications; with no roots, its shipped fallback
//               IsChainTrustedForContextF.Ignored, which trusts any chain: "trust not witnessed";
//   validity    its DocumentValidator's ExpiredValidityInfo verdict at the capture's instant.
// The x5chain is read with com.upokecenter.cbor (not walt.id). One JSON line per case, prefixed
// "WITNESS ", on stdout.

import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifier
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationIdentifierPredicate
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForAttestation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.Ignored
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.msoMdocIssuance
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.usingTrustAnchors
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.HandoverInfo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.IssuerSignedItemsShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.ValidityInfoShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.AccessCertificate
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import id.walt.mdoc.dataelement.ListElement
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.TimeZone
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.net.URI
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import eu.europa.ec.eudi.etsi1196x2.consultation.AttestationClassifications as ConsultationAttestationClassifications

private const val MSO = "eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso"

// The develop profile's verifier.attestation-classifications: the PID docType as pid, the mDL as eaa "mDL".
private val classifications =
    ConsultationAttestationClassifications(
        pids = AttestationIdentifierPredicate.any(setOf(AttestationIdentifier.MDoc("eu.europa.ec.eudi.pid.1"))),
        eaAs = mapOf("mDL" to AttestationIdentifierPredicate.any(setOf(AttestationIdentifier.MDoc("org.iso.18013.5.1.mDL")))),
    )

private fun pem(path: String): List<X509Certificate> =
    File(path).inputStream().use { s ->
        CertificateFactory.getInstance("X.509").generateCertificates(s).map { it as X509Certificate }
    }

private fun trustOf(
    roots: List<X509Certificate>,
    at: String,
): IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor> {
    val pkixDate = Date.from(java.time.Instant.parse(at))
    return roots.toNonEmptyListOrNull()?.let {
        IsChainTrustedForContextF.usingTrustAnchors(it) {
            isRevocationEnabled = false
            date = pkixDate
        }
    } ?: IsChainTrustedForContextF.Ignored
}

@OptIn(ExperimentalTime::class)
private fun validator(
    roots: List<X509Certificate>,
    at: String,
): DeviceResponseValidator =
    DeviceResponseValidator(
        DocumentValidator(
            clock = Clock.fixed(Instant.parse(at), TimeZone.UTC),
            validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
            statusListTokenValidator = null,
            isChainTrustedForAttestation = IsChainTrustedForAttestation(trustOf(roots, at), classifications),
        ),
    )

// HandoverInfo.OpenID4VPHandoverInfo carries a VerifierId; only its clientId enters the
// SessionTranscript. PreRegistered uses the client_id as given, so the capture's x509_hash:...
// value goes in unchanged. The access certificate it also demands is a throwaway, never used.
private val throwaway: AccessCertificate by lazy {
    val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
    val ca = gen.generateKeyPair()
    val leaf = gen.generateKeyPair()
    val now = Date()
    val cert =
        JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                X500Name("CN=unused CA"),
                BigInteger.ONE,
                now,
                Date(now.time + 86_400_000L),
                X500Name("CN=unused"),
                leaf.public,
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(ca.private)),
        )
    val jwk =
        ECKey
            .Builder(Curve.P_256, leaf.public as ECPublicKey)
            .privateKey(leaf.private)
            .x509CertChain(listOf(com.nimbusds.jose.util.Base64.encode(cert.encoded)))
            .build()
    AccessCertificate(jwk, JWSAlgorithm.ES256)
}

private fun handover(h: JsonObject): HandoverInfo.OpenID4VPHandoverInfo {
    val jwk = h["jwk"]?.takeUnless { it is JsonNull }?.let { JWK.parse(it.toString()).toPublicJWK() }
    return HandoverInfo.OpenID4VPHandoverInfo(
        clientId = VerifierId.PreRegistered(h.getValue("client_id").jsonPrimitive.content, throwaway),
        nonce = Nonce(h.getValue("nonce").jsonPrimitive.content),
        ephemeralEncryptionKey = jwk,
        responseUri = URI(h.getValue("response_uri").jsonPrimitive.content).toURL(),
    )
}

// The verifier's own SessionTranscript bytes. toHandover(), SessionTranscript and its
// toDataElement() are private to DocumentValidator.kt, so they are reached by reflection and called
// exactly as ensureValidDeviceAuthentication calls them; toHandover's default sha256 is kept
// (toHandover$default with mask 1). The ListElement is encoded with its own toCBOR().
private fun euTranscript(info: HandoverInfo): ByteArray {
    val kt = Class.forName("$MSO.DocumentValidatorKt")
    val handoverClass = Class.forName("$MSO.Handover")
    val transcriptClass = Class.forName("$MSO.SessionTranscript")
    val toHandover =
        kt
            .getDeclaredMethod(
                "toHandover\$default",
                HandoverInfo::class.java,
                Function1::class.java,
                Int::class.javaPrimitiveType,
                Any::class.java,
            ).apply { isAccessible = true }
    val h = toHandover.invoke(null, info, null, 1, null)
    val transcript =
        transcriptClass
            .getDeclaredConstructor(ByteArray::class.java, ByteArray::class.java, handoverClass)
            .apply { isAccessible = true }
            .newInstance(null, null, h)
    val toDataElement = kt.getDeclaredMethod("toDataElement", transcriptClass).apply { isAccessible = true }
    return (toDataElement.invoke(null, transcript) as ListElement).toCBOR()
}

// Each document's docType and x5chain (leaf first), read with com.upokecenter.cbor.
private fun chains(response: ByteArray): List<Pair<String, List<X509Certificate>>> {
    val factory = CertificateFactory.getInstance("X.509")
    return CBORObject.DecodeFromBytes(response)["documents"].values.map { doc ->
        val unprotected = doc["issuerSigned"]["issuerAuth"][1]
        val x5 = unprotected[CBORObject.FromObject(33)]
        val ders = if (x5.type == CBORType.ByteString) listOf(x5.GetByteString()) else x5.values.map { it.GetByteString() }
        doc["docType"].AsString() to ders.map { factory.generateCertificate(it.inputStream()) as X509Certificate }
    }
}

private fun DocumentError.render(): String =
    when (this) {
        is DocumentError.X5CNotTrusted -> "X5CNotTrusted($cause)"
        is DocumentError.ExpiredValidityInfo -> "ExpiredValidityInfo($validFrom..$validTo)"
        is DocumentError.DeviceKeyNotAuthorizedToSignItems -> "DeviceKeyNotAuthorizedToSignItems($unauthorized)"
        is DocumentError.DevicePublicKeyCannotBeParsed -> "DevicePublicKeyCannotBeParsed(${cause::class.simpleName})"
        is DocumentError.DeviceKeyIsNotEC -> "DeviceKeyIsNotEC(${cause::class.simpleName})"
        is DocumentError.DocumentStatusCheckFailed -> "DocumentStatusCheckFailed(${cause::class.simpleName})"
        else -> this::class.simpleName ?: toString()
    }

private fun failure(e: Throwable) = "${e::class.qualifiedName}: ${e.message}".take(300)

private fun runCase(job: JsonObject): JsonObject {
    val at = job.getValue("at").jsonPrimitive.content
    val roots = job.getValue("roots").jsonArray.flatMap { pem(it.jsonPrimitive.content) }
    val h = job["handover"]?.takeUnless { it is JsonNull }?.jsonObject?.let(::handover)
    val response = File(job.getValue("response").jsonPrimitive.content).readBytes()
    return buildJsonObject {
        put("name", job.getValue("name").jsonPrimitive.content)
        put("at", at)
        put("roots", roots.size)
        put("root_subjects", JsonArray(roots.map { JsonPrimitive(it.subjectX500Principal.name) }))
        // transcript: dumped from the verifier's own construction
        if (h != null) {
            try {
                put("transcript_hex", euTranscript(h).joinToString("") { "%02x".format(it) })
            } catch (e: Throwable) {
                put("transcript_error", failure(e))
            }
        }
        // trust: the verifier's own call, per document
        put(
            "trust",
            JsonArray(
                try {
                    chains(response).map { (docType, chain) ->
                        val v = runBlocking { IsChainTrustedForAttestation(trustOf(roots, at), classifications).msoMdocIssuance(checkNotNull(chain.toNonEmptyListOrNull()) { "empty x5chain" }, docType) }
                        buildJsonObject {
                            put("docType", docType)
                            put("chain", JsonArray(chain.map { JsonPrimitive(it.subjectX500Principal.name) }))
                            put("witnessed", roots.isNotEmpty())
                            when (v) {
                                is CertificationChainValidation.Trusted -> {
                                    put("verdict", "Trusted")
                                    put("anchor", v.trustAnchor.trustedCert?.subjectX500Principal?.name ?: "")
                                }
                                is CertificationChainValidation.NotTrusted -> {
                                    put("verdict", "NotTrusted")
                                    put("cause", v.cause.toString().take(300))
                                }
                                null -> put("verdict", "NoClassification")
                            }
                        }
                    }
                } catch (e: Throwable) {
                    listOf(
                        buildJsonObject {
                            put("verdict", "exception")
                            put("cause", failure(e))
                            put("witnessed", roots.isNotEmpty())
                        },
                    )
                },
            ),
        )
        // the whole DocumentValidator: validity is counted, the walt.id stages are reported only
        try {
            val vp = Base64.getUrlEncoder().withoutPadding().encodeToString(response)
            val result = runBlocking { either<DeviceResponseError, List<id.walt.mdoc.doc.MDoc>> { validator(roots, at).ensureValid(vp, null, h) } }
            result.fold(
                { error ->
                    put("outcome", "refused")
                    when (error) {
                        DeviceResponseError.CannotBeDecoded -> put("error", "CannotBeDecoded")
                        is DeviceResponseError.NotOkDeviceResponseStatus -> put("error", "NotOkDeviceResponseStatus(${error.status})")
                        is DeviceResponseError.InvalidDocuments -> {
                            put("error", "InvalidDocuments")
                            put("errors", JsonArray(error.invalidDocuments.flatMap { d -> d.errors.map { JsonPrimitive(it.render()) } }))
                        }
                    }
                },
                { put("outcome", "accepted") },
            )
        } catch (e: Throwable) {
            put("outcome", "exception")
            put("exception", failure(e))
        }
    }
}

fun main(args: Array<String>) {
    require(args.size == 1) { "usage: WitnessKt JOBS.json" }
    val jobs = Json.parseToJsonElement(File(args[0]).readText()).jsonArray
    require(jobs.isNotEmpty()) { "no cases" }
    for (job in jobs) {
        println("WITNESS " + runCase(job.jsonObject))
    }
    println("WITNESS-DONE ${jobs.size}")
}
