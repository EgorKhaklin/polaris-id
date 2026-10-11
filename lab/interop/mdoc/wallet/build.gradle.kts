// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// ../../eudi-issuer/wallet's build, plus walt.id's mdoc library at the version the EU reference
// verifier endpoint uses (gradle/libs.versions.toml there: waltid 0.11.0). walt.id publishes it to
// its own repository, read anonymously; every artifact is checked against
// gradle/verification-metadata.xml.
plugins {
    kotlin("jvm") version "2.4.20"
    application
}

repositories {
    mavenCentral()
    maven("https://maven.waltid.dev/releases") {
        content { includeGroup("id.walt.mdoc-credentials") }
    }
}

dependencies {
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:0.14.1")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.16.2")
    implementation("id.walt.mdoc-credentials:waltid-mdoc-credentials-jvm:0.11.0")
    implementation("com.augustcellars.cose:cose-java:1.1.0") // walt.id's COSE, at its version; the wallet names its AlgorithmID
    implementation("io.ktor:ktor-client-okhttp:3.6.0")
    implementation("io.ktor:ktor-client-content-negotiation:3.6.0")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.6.0")
    constraints {
        listOf("bcprov", "bcpkix", "bcutil").forEach {
            implementation("org.bouncycastle:$it-jdk18on:1.86") { because("advisories fixed in 1.85") }
        }
        // cose-java 1.1.0 brings com.upokecenter:cbor 4.0.1, which OSV lists (GHSA-fj2w-wfgv-mwq6,
        // fixed in 4.5.1): lifted, as ../../axle/harness lifts its dependencies, not ignored.
        implementation("com.upokecenter:cbor:4.5.6") { because("GHSA-fj2w-wfgv-mwq6 fixed in 4.5.6") }
    }
}

// cose-java 1.1.0 also brings net.i2p.crypto:eddsa 0.3.0 (GHSA-p53j-g8pw-4w5f, no fixed release).
// It serves EdDSA only; this wallet signs ES256, so it is left out of the build.
configurations.configureEach { exclude(group = "net.i2p.crypto", module = "eddsa") }

kotlin { jvmToolchain(21) }

application { mainClass.set("MainKt") }
