# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/unittest
import ../boringssl

suite "boringssl P-256":
  test "sign and verify a digest":
    let key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
    require key != nil
    defer:
      EC_KEY_free(key)
    require EC_KEY_generate_key(key) == 1

    var digest: array[32, uint8]
    let signature = ECDSA_do_sign(addr digest[0], digest.len.csize_t, key)
    require signature != nil
    defer:
      ECDSA_SIG_free(signature)

    check ECDSA_do_verify(addr digest[0], digest.len.csize_t, signature, key) == 1
    digest[0] = 1
    check ECDSA_do_verify(addr digest[0], digest.len.csize_t, signature, key) == 0
