# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

## TLS records are decrypted in place in the connection's read buffer. With
## `-d:BORINGSSL_ZERO_RECORD_BUFFERS=true` the fork allocates that buffer with
## `OPENSSL_malloc`, so `OPENSSL_free` zeroes it
## (boringssl/.vac/patches/ssl-buffer-zeroing.patch); by default it is
## upstream's plain malloc/free. This test sends 256 KiB (16 full records) over
## an in-memory TLS 1.3 connection and counts the blocks BoringSSL frees that
## still hold the plaintext: none with the option, some without it (the
## default is unchanged). `nimble test_zero_record_buffers` runs the option.

import std/unittest
import ../boringssl

const scanSupported = defined(macosx) or (defined(linux) and not defined(android))

when scanSupported:
  {.compile: "support/freescan.c".}
  proc freescanSet(p: pointer, n: csize_t) {.importc: "freescan_set", cdecl.}
  proc freescanHits(): cint {.importc: "freescan_hits", cdecl.}

  const
    MbstringAsc = 0x1001.cint
    PayloadLen = 256 * 1024

  proc newKey(): ptr EVP_PKEY =
    let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC.cint, nil)
    doAssert pctx != nil
    doAssert EVP_PKEY_keygen_init(pctx) == 1
    doAssert EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 1
    result = nil
    doAssert EVP_PKEY_keygen(pctx, addr result) == 1
    EVP_PKEY_CTX_free(pctx)

  proc selfSigned(key: ptr EVP_PKEY): ptr X509 =
    result = X509_new()
    doAssert X509_set_version(result, X509_VERSION_3) == 1
    doAssert ASN1_INTEGER_set(X509_get_serialNumber(result), 1) == 1
    doAssert X509_gmtime_adj(X509_getm_notBefore(result), -3600) != nil
    doAssert X509_gmtime_adj(X509_getm_notAfter(result), 3600) != nil
    let name = X509_get_subject_name(result)
    let cn = "zeroing-test"
    doAssert X509_NAME_add_entry_by_NID(
      name, NID_commonName, MbstringAsc, cast[ptr uint8](cn.cstring), cn.len.cint, -1, 0
    ) == 1
    doAssert X509_set_issuer_name(result, name) == 1
    doAssert X509_set_pubkey(result, key) == 1
    doAssert X509_sign(result, key, EVP_sha256()) > 0

  proc newConn(ctx: ptr SSL_CTX, server: bool): (ptr SSL, ptr BIO, ptr BIO) =
    let ssl = SSL_new(ctx)
    let rbio = BIO_new(BIO_s_mem())
    let wbio = BIO_new(BIO_s_mem())
    SSL_set_bio(ssl, rbio, wbio)
    if server:
      SSL_set_accept_state(ssl)
    else:
      SSL_set_connect_state(ssl)
    (ssl, rbio, wbio)

  proc pump(fromW, toR: ptr BIO) =
    var buf: array[16384, uint8]
    while BIO_pending(fromW) > 0:
      let n = BIO_read(fromW, addr buf[0], buf.len.cint)
      doAssert n > 0
      doAssert BIO_write(toR, addr buf[0], n) == n

suite "boringssl TLS record buffers":
  test (
    if boringsslZeroRecordBuffers:
      "with BORINGSSL_ZERO_RECORD_BUFFERS, decrypted records are zeroed before their buffer is freed"
    else:
      "by default, as upstream, freed record buffers still hold the plaintext"
  ):
    when not scanSupported:
      skip()
    else:
      let key = newKey()
      let cert = selfSigned(key)
      let sctx = SSL_CTX_new(TLS_method())
      let cctx = SSL_CTX_new(TLS_method())
      for ctx in [sctx, cctx]:
        doAssert SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION.uint16) == 1
      doAssert SSL_CTX_use_certificate(sctx, cert) == 1
      doAssert SSL_CTX_use_PrivateKey(sctx, key) == 1
      let (s, sr, sw) = newConn(sctx, true)
      let (c, cr, cw) = newConn(cctx, false)
      var cdone, sdone = false
      for _ in 0 ..< 10:
        if not cdone:
          cdone = SSL_do_handshake(c) == 1
        pump(cw, sr)
        if not sdone:
          sdone = SSL_do_handshake(s) == 1
        pump(sw, cr)
        if cdone and sdone:
          break
      check cdone and sdone

      var marker: array[32, uint8]
      for i in 0 ..< marker.len:
        marker[i] = uint8(0xA5 xor i)
      var payload = newSeq[uint8](PayloadLen)
      for i in 0 ..< payload.len:
        payload[i] = marker[i mod marker.len]
      freescanSet(addr marker[0], marker.len.csize_t)

      var sent = 0
      while sent < payload.len:
        let n = SSL_write(c, addr payload[sent], cint(min(16384, payload.len - sent)))
        doAssert n > 0
        sent += n
      pump(cw, sr)
      var got = 0
      var buf = newSeq[uint8](16384)
      while got < payload.len:
        let n = SSL_read(s, addr buf[0], buf.len.cint)
        doAssert n > 0
        got += n
      check got == payload.len
      # The application's own copies are not the library's to erase.
      for i in 0 ..< buf.len:
        buf[i] = 0
      for i in 0 ..< payload.len:
        payload[i] = 0
      let afterRead = freescanHits()

      SSL_free(c)
      SSL_free(s)
      let afterFree = freescanHits()
      checkpoint "freed blocks holding the plaintext: " & $afterRead &
        " after the read, " & $afterFree & " after SSL_free"
      if boringsslZeroRecordBuffers:
        check afterRead == 0
        check afterFree == 0
      else:
        check afterRead > 0
      freescanSet(nil, 0)
      SSL_CTX_free(cctx)
      SSL_CTX_free(sctx)
      X509_free(cert)
      EVP_PKEY_free(key)
