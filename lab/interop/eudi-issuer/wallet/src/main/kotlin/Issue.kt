// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// Issuance. The EU reference OpenID4VCI library does the protocol against the EU reference issuer:
// issuer and authorization server metadata, the pushed authorization request with PKCE, the token
// request, DPoP throughout, attestation-based client authentication, the nonce, the JWT proof, and
// the encrypted credential response. The wallet does what the library leaves to a wallet: it logs
// the user in at the authorization server, and its wallet provider attests the client and the key.
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.AttestationBasedClientAuthenticationSpec
import eu.europa.ec.eudi.openid4vci.AuthorizationCode
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.Credential
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.DPoPConfig
import eu.europa.ec.eudi.openid4vci.DPoPUsage
import eu.europa.ec.eudi.openid4vci.EncryptionSupportConfig
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.IssuanceRequestPayload
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.OpenId4VCISpec
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import eu.europa.ec.eudi.openid4vci.ProvisionDPoPSigner
import eu.europa.ec.eudi.openid4vci.Signer
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Parameters
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID
import kotlin.system.exitProcess

// The realm's client for attested wallets, its redirect URI and test user, and the PID's
// configuration id, all as the issuer's own docker-compose sets them up.
private const val CLIENT_ID = "eudiw-abca"
private val REDIRECT_URI = URI.create("eudi-openid4ci://authorize")
private const val TEST_USER = "tneal"
private const val TEST_PASSWORD = "password"
private val PID = CredentialConfigurationIdentifier("eu.europa.ec.eudi.pid_vc_sd_jwt")
private val ES256 = JwsAlgorithm(JWSAlgorithm.ES256.name)

suspend fun issue(args: List<String>) {
    if (args.size != 6) {
        System.err.println(
            "usage: wallet issue <issuer-url> <wallet-provider-key.pem> <wallet-provider.pem> " +
                "<status-list-uri> <credential-out> <holder-key-out>",
        )
        exitProcess(2)
    }
    val issuerId = CredentialIssuerId(args[0]).getOrThrow()
    val provider = WalletProvider(loadEcPrivateKey(args[1]), loadCertificate(args[2]), URI.create(args[3]))
    val instanceKey = newKey() // the wallet instance's key, which the client attestation binds
    val dpopKey = newKey()
    val deviceKey = newKey() // the key the PID is bound to, which the key attestation attests

    val config = OpenId4VCIConfig(
        clientAuthentication = ClientAuthentication.AttestationBased(CLIENT_ID, provider.clientAttestation(instanceKey)),
        authFlowRedirectionURI = REDIRECT_URI,
        encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),
        dPoPUsage = DPoPUsage.Required(
            DPoPConfig(
                object : ProvisionDPoPSigner {
                    override val popAlgorithm = ES256

                    override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> =
                        signer(dpopKey, dpopKey.toPublicJWK())
                },
            ),
        ),
        parUsage = ParUsage.Required(),
    )
    val http = HttpClient(OkHttp) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    }
    http.use {
        val issuer = Issuer.makeWalletInitiated(config, issuerId, listOf(PID), it).getOrThrow().first
        val prepared = issuer.prepareAuthorizationRequest().getOrThrow()
        val redirect = login(prepared.authorizationCodeURL.toString())
        val authorized = with(issuer) {
            prepared.authorizeWithAuthorizationCode(
                AuthorizationCode(redirect.getValue("code")),
                redirect.getValue("state"),
                issuer = redirect["iss"],
            ).getOrThrow()
        }
        println("authorized ${authorized.accessToken::class.simpleName} access token for $TEST_USER")

        val proof = ProofSpecification.JwtProofWithKeyAttestation { nonce, period ->
            signer(deviceKey, provider.keyAttestation(deviceKey, nonce, period))
        }
        val (_, outcome) = with(issuer) {
            authorized.request(IssuanceRequestPayload.ConfigurationBased(PID), proof).getOrThrow()
        }
        when (outcome) {
            is SubmissionOutcome.Success -> {
                val credential = (outcome.credentials.first().credential as Credential.Str).value
                File(args[4]).writeText(credential)
                File(args[5]).writeText(deviceKey.toJSONString())
                println("ISSUED ${PID.value}, ${credential.count { c -> c == '~' } - 1} disclosures, bound to the attested key")
            }
            is SubmissionOutcome.Deferred -> {
                println("REFUSED: the issuer deferred issuance (${outcome.transactionId.value})")
                exitProcess(4)
            }
            is SubmissionOutcome.Failed -> {
                println("REFUSED by the issuer: ${outcome.error}")
                exitProcess(4)
            }
        }
    }
}

/**
 * Logs the test user in at Keycloak's login form, over HTTP, as a browser would: it opens the
 * authorization URL the library prepared, posts the form, and reads the parameters of the redirect
 * to the wallet. Returns them (code, state, iss).
 */
suspend fun login(authorizationUrl: String): Map<String, String> = HttpClient(OkHttp) {
    install(HttpCookies)
    followRedirects = false
}.use { browser ->
    var page: HttpResponse = browser.get(authorizationUrl)
    repeat(5) { page.headers[HttpHeaders.Location]?.let { page = browser.get(it) } }
    val html = page.bodyAsText()
    val action = Regex("""<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"""").find(html)?.groupValues?.get(1)
        ?: error("no login form at the authorization endpoint (HTTP ${page.status})")
    val response = browser.submitForm(
        url = action.replace("&amp;", "&"),
        formParameters = Parameters.build {
            append("username", TEST_USER)
            append("password", TEST_PASSWORD)
            append("credentialId", "")
        },
    )
    val location = response.headers[HttpHeaders.Location]
        ?: error("the login was not redirected to the wallet (HTTP ${response.status})")
    require(location.startsWith(REDIRECT_URI.toString())) { "redirected elsewhere: $location" }
    URI(location).rawQuery.split("&").associate { pair ->
        val (name, value) = pair.split("=", limit = 2).map { part -> URLDecoder.decode(part, Charsets.UTF_8) }
        name to value
    }
}

/**
 * The test wallet provider: it attests the wallet instance (the client attestation, for
 * attestation-based client authentication) and the device key (the key attestation in the JWT
 * proof), both signed under its certificate in `x5c`, both pointing at its status list.
 */
class WalletProvider(private val key: ECPrivateKey, certificate: X509Certificate, private val statusList: URI) {
    private val x5c = listOf(Base64.encode(certificate.encoded))

    private fun status(index: Int, expires: Instant) = mapOf(
        "status" to mapOf("status_list" to mapOf("idx" to index, "uri" to statusList.toString())),
        "exp" to expires.epochSecond,
    )

    private fun sign(type: String, claims: JWTClaimsSet): SignedJWT =
        SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(type)).x509CertChain(x5c).build(), claims)
            .apply { sign(ECDSASigner(key)) }

    /** At least the period the issuer asks for (31 days for its PID), and 90 days by default. */
    private fun until(period: PositiveDuration?): Instant =
        Instant.now() + maxOf(Duration.ofDays(90), (period?.value ?: Duration.ZERO) + Duration.ofDays(1))

    fun clientAttestation(instanceKey: ECKey): ProvisionClientAttestation = object : ProvisionClientAttestation {
        override val algorithm = ES256
        override val popAlgorithm = ES256

        override suspend fun invoke(
            authorizationServer: HttpsUrl,
            preferredClientStatusPeriod: PositiveDuration?,
        ): ProvisionClientAttestation.Provisioned {
            val now = Instant.now()
            val claims = JWTClaimsSet.Builder()
                .issuer("polaris-lab-test-wallet-provider")
                .subject(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now + Duration.ofHours(1)))
                .claim("cnf", mapOf("jwk" to instanceKey.toPublicJWK().toJSONObject()))
                .claim("wallet_name", "Polaris lab wallet")
                .claim("wallet_version", "1.0.0")
                .claim("wallet_solution_certification_information", "https://example.org/polaris-lab-wallet")
                .claim("client_status", status(0, until(preferredClientStatusPeriod)))
                .build()
            val attestation = sign(AttestationBasedClientAuthenticationSpec.ATTESTATION_JWT_TYPE, claims)
            return ProvisionClientAttestation.Provisioned(
                ClientAttestationJWT(attestation.serialize()),
                signer(instanceKey, instanceKey.toPublicJWK()),
            )
        }
    }

    fun keyAttestation(deviceKey: ECKey, nonce: Nonce?, period: PositiveDuration?): KeyAttestationJWT {
        val now = Instant.now()
        val claims = JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now + Duration.ofHours(1)))
            .jwtID(UUID.randomUUID().toString())
            .claim(OpenId4VCISpec.ATTESTED_KEYS, listOf(deviceKey.toPublicJWK().toJSONObject()))
            .claim(OpenId4VCISpec.KEY_STORAGE, listOf(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_HIGH))
            .claim(OpenId4VCISpec.USER_AUTHENTICATION, listOf(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_HIGH))
            .claim(OpenId4VCISpec.CERTIFICATION, "https://example.org/polaris-lab-wallet/key-storage")
            .claim("key_storage_status", status(1, until(period)))
            .apply { nonce?.let { claim(OpenId4VCISpec.NONCE, it.value) } }
            .build()
        return KeyAttestationJWT(sign(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE, claims))
    }
}
