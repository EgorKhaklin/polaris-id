# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_card - the physical token: the card profile, its reference codec, and the emulator.

The schema has modelled the card since the beginning (serials, biometric binding type, duress
hash, succession). This package is where the card stops being a set of columns and becomes an
object with an encoding somebody else can implement. See docs/design/card-profile.md.
"""
