// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on the EU reference libraries. `issue` obtains a PID from the EU reference issuer over
// OpenID4VCI (Issue.kt); `present` presents it to polaris-oid4vp over OpenID4VP (Present.kt).
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.SignFunction
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import kotlin.system.exitProcess

fun main(args: Array<String>): Unit = runBlocking {
    when (args.firstOrNull()) {
        "issue" -> issue(args.drop(1))
        "present" -> present(args.drop(1))
        else -> {
            System.err.println("usage: wallet issue ... | wallet present ...")
            exitProcess(2)
        }
    }
}

fun newKey(): ECKey = ECKeyGenerator(Curve.P_256).generate()

/** A P-256 key as the OpenID4VCI library's [Signer]: it signs with the JDK and the library encodes the JWS. */
fun <PUB> signer(key: ECKey, publicMaterial: PUB): Signer<PUB> = object : Signer<PUB> {
    override val javaAlgorithm = "SHA256withECDSA"

    override suspend fun acquire(): SignOperation<PUB> = SignOperation(
        SignFunction { input ->
            Signature.getInstance(javaAlgorithm).run {
                initSign(key.toECPrivateKey())
                update(input)
                sign()
            }
        },
        publicMaterial,
    )

    override suspend fun release(signOperation: SignOperation<PUB>?) = Unit
}

fun loadCertificate(path: String): X509Certificate =
    CertificateFactory.getInstance("X.509").generateCertificate(File(path).inputStream()) as X509Certificate

fun loadEcPrivateKey(path: String): ECPrivateKey {
    val der = Base64.getMimeDecoder().decode(
        File(path).readText().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", ""),
    )
    return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der)) as ECPrivateKey
}
