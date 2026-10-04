// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on Multipaz, the OpenWallet Foundation's identity credential library (Kotlin
// Multiplatform, its JVM target), to present to polaris-oid4vp.
plugins {
    kotlin("jvm") version "2.4.20"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("org.multipaz:multipaz:0.101.0")
    // Multipaz's own HTTP engine on the JVM (a runtime dependency of it); the wallet names it to
    // hand it to uriSchemePresentment().
    implementation("io.ktor:ktor-client-java:3.3.3")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("WalletKt") }
