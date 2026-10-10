// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A harness written here that drives Axle's Kotlin OpenID4VP client, to present to polaris-oid4vp.
plugins {
    // The Kotlin version Axle's own build declares (kotlin/build.gradle.kts at the pinned commit).
    kotlin("jvm") version "2.2.21"
    application
}

repositories { mavenCentral() }

dependencies {
    // Axle's public modules, resolved from the included build: the OpenID4VP client, the X.509
    // request verifier, and the software secure area Axle ships for desktop and server hosts.
    implementation("com.hopae.eudi:openid4vp:0.0.1-SNAPSHOT")
    implementation("com.hopae.eudi:trust:0.0.1-SNAPSHOT")
    implementation("com.hopae.eudi:testkit:0.0.1-SNAPSHOT")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}

kotlin { jvmToolchain(17) }

application { mainClass.set("HolderKt") }
