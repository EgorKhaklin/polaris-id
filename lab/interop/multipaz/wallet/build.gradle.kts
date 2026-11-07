// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on Multipaz, the OpenWallet Foundation's identity credential library (Kotlin
// Multiplatform, its JVM target), to present to polaris-oid4vp.
plugins {
    kotlin("jvm") version "2.4.21"
    application
}

repositories {
    mavenCentral()
    google { content { includeGroup("com.android.keyattestation"); includeGroup("androidx.annotation") } }
}

dependencies {
    implementation("org.multipaz:multipaz:0.102.0")
    // Multipaz's own HTTP engine on the JVM (a runtime dependency of it); the wallet names it to
    // hand it to uriSchemePresentment().
    implementation("io.ktor:ktor-client-java:3.6.1")
    // The key attestation verifier Multipaz 0.102.0 adds pulls these in; they resolve at the releases
    // scripts/polaris-osv-gradle.sh accepts.
    constraints {
        implementation("com.google.guava:guava:33.7.2-jre")
        implementation("org.bouncycastle:bcprov-jdk18on:1.86")
        implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
        implementation("org.bouncycastle:bcutil-jdk18on:1.86")
    }
}

kotlin { jvmToolchain(21) }

application { mainClass.set("WalletKt") }
