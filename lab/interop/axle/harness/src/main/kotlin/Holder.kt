// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A harness written here that drives Axle's Kotlin OpenID4VP client: it presents one SD-JWT VC
// to polaris-oid4vp over OpenID4VP 1.0, once per job ../run.sh hands it.
//
//   polaris-axle-harness <dir>
//
// It makes the holder key in Axle's SoftwareSecureArea and writes only its public half to
// <dir>/holder-jwk.json. Then it waits for jobs: <dir>/jobs/<n>.job holds three lines, a launch
// URI, a credential file and the CA the wallet trusts for the verifier's request object. The
// answer goes to <dir>/jobs/<n>.out, and <dir>/jobs/<n>.done marks it complete. <dir>/jobs/stop
// ends the process. The key lives only in this process's memory, so every job signs with it.
//
// Axle's code does the protocol: Openid4VpClient.resolveRequest fetches the signed request object
// (by POST when the launch URI says so, with a wallet_nonce it then requires echoed), checks its
// typ and client_id, and X509RequestVerifier checks its signature against the x5c leaf, the
// x509_hash client identifier, and whether the chain reaches the anchor. DcqlEngine matches the
// query, HeldSdJwtVc builds the presentation and its key binding JWT (signed through the secure
// area), and Openid4VpClient.respond encrypts it to the verifier's key and posts it
// (direct_post.jwt). This file supplies what an app supplies: the HTTP transport (Axle's
// HttpTransport port), the trust anchor, and the consent step. Axle reports an untrusted verifier
// as VerifierInfo.trusted = false and leaves the decision to the app; this harness then declines.
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.trust.TrustAnchors
import com.hopae.eudi.wallet.trust.X509ChainValidator
import com.hopae.eudi.wallet.trust.X509RequestVerifier
import com.hopae.eudi.wallet.vp.HeldSdJwtVc
import com.hopae.eudi.wallet.vp.Openid4VpClient
import com.hopae.eudi.wallet.vp.PresentationSelection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.system.exitProcess

private fun pem(file: File): X509Certificate =
    CertificateFactory.getInstance("X.509").generateCertificate(file.inputStream()) as X509Certificate

/**
 * Axle's HttpTransport port over the JDK's HTTP client. It trusts one certificate for TLS: the
 * verifier listener's own, which polaris-oid4vp keygen makes self-signed. It follows no redirects.
 */
private class JdkTransport(listener: X509Certificate, private val log: (String) -> Unit) : HttpTransport {
    private val client: HttpClient = run {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("verifier-listener", listener)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val tls = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
        HttpClient.newBuilder().sslContext(tls).followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10)).build()
    }

    override suspend fun execute(request: HttpRequest): HttpResponse {
        val builder = java.net.http.HttpRequest.newBuilder(URI(request.url)).timeout(Duration.ofSeconds(30))
        request.headers.forEach { (name, value) -> builder.header(name, value) }
        val body = request.body?.let { java.net.http.HttpRequest.BodyPublishers.ofByteArray(it) }
            ?: java.net.http.HttpRequest.BodyPublishers.noBody()
        builder.method(request.method.name, body)
        val response = withContext(Dispatchers.IO) {
            client.send(builder.build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray())
        }
        log("HTTP ${request.method} ${URI(request.url).path} -> ${response.statusCode()}")
        val headers = response.headers().map().flatMap { (name, values) -> values.map { name to it } }
        return HttpResponse(response.statusCode(), headers, response.body())
    }
}

private suspend fun present(
    area: SoftwareSecureArea, key: KeyInfo, listener: X509Certificate,
    launchUri: String, credentialFile: File, anchorFile: File, out: StringBuilder,
) {
    fun say(line: String) { out.append(line).append('\n') }

    val held = try {
        HeldSdJwtVc("credential-1", SdJwt.parseFromIssuer(credentialFile.readText().trim()),
            SecureAreaJwsSigner(area, key.handle, SigningAlgorithm.ES256))
    } catch (e: Exception) {
        say("CREDENTIAL REFUSED ${e::class.simpleName}: ${e.message}")
        return
    }

    val validator = X509ChainValidator(TrustAnchors(listOf(pem(anchorFile))))
    val client = Openid4VpClient(
        http = JdkTransport(listener, ::say),
        clock = { System.currentTimeMillis() / 1000 },
        trust = X509RequestVerifier(validator),
        rng = Rng.Default,
    )

    val request = try {
        client.resolveRequest(launchUri)
    } catch (e: Exception) {
        say("REQUEST REFUSED ${e::class.simpleName}: ${e.message}")
        return
    }
    say("REQUEST client_id ${request.clientId}, response_mode ${request.responseMode}")

    // Axle's verdict on the verifier. X509RequestVerifier keeps the reason to itself, so on a
    // refusal the same Axle validator is asked again, only to print why.
    val verifier = request.verifier
    if (!verifier.trusted) {
        val why = runCatching { validator.validate(verifier.certificateChainDer.orEmpty()) }.exceptionOrNull()?.message
        say("TRUST not trusted (${verifier.commonName}): $why")
        say("DECLINED the verifier is not trusted; nothing was sent")
        return
    }
    say("TRUST trusted (${verifier.commonName})")

    val matches = client.match(request, listOf(held))
    if (!matches.isSatisfiable()) {
        say("DECLINED no held credential satisfies the query")
        return
    }
    try {
        val result = client.respond(request, matches, PresentationSelection.auto(matches), listOf(held))
        say("DISPATCHED the verifier answered 2xx, redirect_uri ${result.redirectUri}")
    } catch (e: Exception) {
        say("DISPATCH FAILED ${e::class.simpleName}: ${e.message}")
    }
}

fun main(args: Array<String>) = runBlocking {
    if (args.size != 1) {
        System.err.println("usage: polaris-axle-harness <dir>")
        exitProcess(2)
    }
    val dir = File(args[0])
    val jobs = File(dir, "jobs").apply { mkdirs() }

    // The holder key, made by Axle's software secure area; only its public half leaves.
    val area = SoftwareSecureArea()
    val key = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
    File(dir, "holder-jwk.json.tmp").writeText(JwkEc.toJson(key.publicKey).serialize())
    File(dir, "holder-jwk.json.tmp").renameTo(File(dir, "holder-jwk.json"))
    println("harness ready, holder key ${key.handle.alias} in ${area.id}")

    val listener = pem(File(dir, "pki/tls.pem"))
    while (!File(jobs, "stop").exists()) {
        val job = jobs.listFiles { f -> f.name.endsWith(".job") }?.minByOrNull { it.name }
        if (job == null) {
            Thread.sleep(100)
            continue
        }
        val name = job.name.removeSuffix(".job")
        val (launchUri, credential, anchor) = job.readLines().map { it.trim() }
        val out = StringBuilder()
        try {
            present(area, key, listener, launchUri, File(dir, credential), File(dir, anchor), out)
        } catch (e: Exception) {
            out.append("HARNESS ERROR ${e::class.simpleName}: ${e.message}\n")
        }
        File(jobs, "$name.out").writeText(out.toString())
        job.delete()
        File(jobs, "$name.done").writeText("")
        print(out)
    }
    println("harness stopped")
}
