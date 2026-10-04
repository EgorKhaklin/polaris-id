// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on vck, A-SIT Plus's Kotlin Multiplatform credential library, to present to
// polaris-oid4vp. vck issues the credential too, so the verifier is the only Polaris software in
// the exchange.
plugins {
    kotlin("jvm") version "2.4.20"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("at.asitplus.wallet:vck-openid-ktor:8.0.0")
    // vck-openid-ktor uses this engine internally; the wallet names it to hand vck its client.
    implementation("io.ktor:ktor-client-cio:3.5.2")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("WalletKt") }
