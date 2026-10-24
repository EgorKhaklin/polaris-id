// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// Lifts, in every build of the composite (the harness and Axle's included build), the dependencies
// OSV lists advisories against to the releases that fix them, as an operator would, rather than
// ignore the advisories. Axle's source is not changed: ../run.sh passes this file to Gradle.
//
// Kotlin Gradle Plugin 2.2.21, which both builds declare: fixed in 2.4.20. Bouncy Castle 1.78.1, in
// Axle's test fixtures: fixed in 1.85, lifted to 1.86 as Axle's own pull request #93 does. With
// the plugin at 2.4.21, the OpenTelemetry 1.41.0 and Bouncy Castle 1.80 (bcpg, bcpkix, and bcprov
// and bcutil 1.80.2) components that 2.2.21's own classpaths brought no longer resolve, so
// nothing here names them.
val kotlinPlugin = "2.4.21"
val lifts = listOf(
    "org.bouncycastle:bcprov-jdk18on:1.86",
    "org.bouncycastle:bcpkix-jdk18on:1.86",
    "org.bouncycastle:bcutil-jdk18on:1.86",
)

beforeSettings {
    pluginManagement.resolutionStrategy.eachPlugin {
        if (requested.id.namespace == "org.jetbrains.kotlin") useVersion(kotlinPlugin)
    }
}

allprojects {
    configurations.configureEach {
        if (isCanBeDeclared) {
            lifts.forEach { dependencyConstraints.add(project.dependencies.constraints.create(it) { because("OSV advisories fixed") }) }
        }
    }
}
