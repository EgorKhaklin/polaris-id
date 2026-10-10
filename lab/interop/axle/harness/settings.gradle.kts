// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
rootProject.name = "polaris-axle-harness"

// Axle's Kotlin SDK, a source checkout at the commit ../run.sh pins, joined as an included build:
// its modules are used as they are, and nothing of it is changed.
includeBuild(System.getenv("AXLE_KOTLIN") ?: error("set AXLE_KOTLIN to the checkout's kotlin/ directory"))
