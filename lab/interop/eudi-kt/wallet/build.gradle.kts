// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on the EU reference OpenID4VP library (eudi-lib-jvm-openid4vp-kt), to present to polaris-oid4vp.
plugins {
    kotlin("jvm") version "2.2.21"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.16.2")
    implementation("io.ktor:ktor-client-okhttp:3.3.3")
    implementation("io.ktor:ktor-client-content-negotiation:3.3.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.3.3")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("WalletKt") }
