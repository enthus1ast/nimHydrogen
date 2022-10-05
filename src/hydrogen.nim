{.passl:"-lhydrogen -L./".}

proc hydro_init*(): cint {.cdecl, importc: "hydro_init".}
##  ----------------

const
  hydro_random_SEEDBYTES* = 32

proc hydro_random_u32*(): uint32 {.cdecl, importc: "hydro_random_u32".}
proc hydro_random_uniform*(upper_bound: uint32): uint32 {.cdecl,
    importc: "hydro_random_uniform".}
proc hydro_random_buf*(outp: pointer; out_len: csize_t) {.cdecl,
    importc: "hydro_random_buf".}
proc hydro_random_buf_deterministic*(outp: pointer; out_len: csize_t; seed: array[
    hydro_random_SEEDBYTES, uint8]) {.cdecl,
                                      importc: "hydro_random_buf_deterministic".}
proc hydro_random_ratchet*() {.cdecl, importc: "hydro_random_ratchet".}
proc hydro_random_reseed*() {.cdecl, importc: "hydro_random_reseed".}
##  ----------------

const
  hydro_hash_BYTES* = 32
  hydro_hash_BYTES_MAX* = 65535
  hydro_hash_BYTES_MIN* = 16
  hydro_hash_CONTEXTBYTES* = 8
  hydro_hash_KEYBYTES* = 32

type
  hydro_hash_state* {.bycopy.} = object
    state*: array[12, uint32]
    buf_off*: uint8
    align*: array[3, uint8]


proc hydro_hash_keygen*(key: array[hydro_hash_KEYBYTES, uint8]) {.cdecl,
    importc: "hydro_hash_keygen".}
proc hydro_hash_init*(state: ptr hydro_hash_state;
                     ctx: array[hydro_hash_CONTEXTBYTES, char];
                     key: array[hydro_hash_KEYBYTES, uint8]): cint {.cdecl,
    importc: "hydro_hash_init".}
proc hydro_hash_update*(state: ptr hydro_hash_state; inp: pointer; in_len: csize_t): cint {.
    cdecl, importc: "hydro_hash_update".}
proc hydro_hash_final*(state: ptr hydro_hash_state; outp: ptr uint8;
                      out_len: csize_t): cint {.cdecl, importc: "hydro_hash_final".}
proc hydro_hash_hash*(outp: ptr uint8; out_len: csize_t; inp: pointer;
                     in_len: csize_t; ctx: array[hydro_hash_CONTEXTBYTES, char];
                     key: array[hydro_hash_KEYBYTES, uint8]): cint {.cdecl,
    importc: "hydro_hash_hash".}
##  ----------------

const
  hydro_secretbox_CONTEXTBYTES* = 8
  hydro_secretbox_HEADERBYTES* = (20 + 16)
  hydro_secretbox_KEYBYTES* = 32
  hydro_secretbox_PROBEBYTES* = 16

proc hydro_secretbox_keygen*(key: array[hydro_secretbox_KEYBYTES, uint8]) {.cdecl,
    importc: "hydro_secretbox_keygen".}
proc hydro_secretbox_encrypt*(c: ptr uint8; m: pointer; mlen: csize_t;
                             msg_id: uint64;
                             ctx: array[hydro_secretbox_CONTEXTBYTES, char];
                             key: array[hydro_secretbox_KEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_secretbox_encrypt".}
proc hydro_secretbox_decrypt*(m: pointer; c: ptr uint8; clen: csize_t;
                             msg_id: uint64;
                             ctx: array[hydro_secretbox_CONTEXTBYTES, char];
                             key: array[hydro_secretbox_KEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_secretbox_decrypt".}
proc hydro_secretbox_probe_create*(probe: array[hydro_secretbox_PROBEBYTES, uint8];
                                  c: ptr uint8; c_len: csize_t; ctx: array[
    hydro_secretbox_CONTEXTBYTES, char];
                                  key: array[hydro_secretbox_KEYBYTES, uint8]) {.
    cdecl, importc: "hydro_secretbox_probe_create".}
proc hydro_secretbox_probe_verify*(probe: array[hydro_secretbox_PROBEBYTES, uint8];
                                  c: ptr uint8; c_len: csize_t; ctx: array[
    hydro_secretbox_CONTEXTBYTES, char];
                                  key: array[hydro_secretbox_KEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_secretbox_probe_verify".}
##  ----------------

const
  hydro_kdf_CONTEXTBYTES* = 8
  hydro_kdf_KEYBYTES* = 32
  hydro_kdf_BYTES_MAX* = 65535
  hydro_kdf_BYTES_MIN* = 16

proc hydro_kdf_keygen*(key: array[hydro_kdf_KEYBYTES, uint8]) {.cdecl,
    importc: "hydro_kdf_keygen".}
proc hydro_kdf_derive_from_key*(subkey: ptr uint8; subkey_len: csize_t;
                               subkey_id: uint64;
                               ctx: array[hydro_kdf_CONTEXTBYTES, char];
                               key: array[hydro_kdf_KEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_kdf_derive_from_key".}
##  ----------------

const
  hydro_sign_BYTES* = 64
  hydro_sign_CONTEXTBYTES* = 8
  hydro_sign_PUBLICKEYBYTES* = 32
  hydro_sign_SECRETKEYBYTES* = 64
  hydro_sign_SEEDBYTES* = 32

type
  Signature* = array[hydro_sign_BYTES, uint8]
  PublicKey* = array[hydro_sign_PUBLICKEYBYTES, uint8]
  SecretKey* = array[hydro_sign_SECRETKEYBYTES, uint8]

type
  hydro_sign_state* {.bycopy.} = object
    hash_st*: hydro_hash_state

  hydro_sign_keypair* {.bycopy.} = object
    pk*: array[hydro_sign_PUBLICKEYBYTES, uint8]
    sk*: array[hydro_sign_SECRETKEYBYTES, uint8]


proc hydro_sign_keygen*(kp: ptr hydro_sign_keypair) {.cdecl,
    importc: "hydro_sign_keygen".}
proc hydro_sign_keygen_deterministic*(kp: ptr hydro_sign_keypair;
                                     seed: array[hydro_sign_SEEDBYTES, uint8]) {.
    cdecl, importc: "hydro_sign_keygen_deterministic".}
proc hydro_sign_init*(state: ptr hydro_sign_state;
                     ctx: array[hydro_sign_CONTEXTBYTES, char]): cint {.cdecl,
    importc: "hydro_sign_init".}
proc hydro_sign_update*(state: ptr hydro_sign_state; m: pointer; mlen: csize_t): cint {.
    cdecl, importc: "hydro_sign_update".}
proc hydro_sign_final_create*(state: ptr hydro_sign_state;
                             csig: Signature;
                             sk: array[hydro_sign_SECRETKEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_sign_final_create".}
proc hydro_sign_final_verify*(state: ptr hydro_sign_state;
                             csig: Signature;
                             pk: array[hydro_sign_PUBLICKEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_sign_final_verify".}
proc hydro_sign_create*(csig: Signature; m: pointer;
                       mlen: csize_t; ctx: array[hydro_sign_CONTEXTBYTES, char];
                       sk: array[hydro_sign_SECRETKEYBYTES, uint8]): cint {.cdecl,
    importc: "hydro_sign_create".}
proc hydro_sign_verify*(csig: Signature; m: pointer;
                       mlen: csize_t; ctx: array[hydro_sign_CONTEXTBYTES, char];
                       pk: array[hydro_sign_PUBLICKEYBYTES, uint8]): cint {.cdecl,
    importc: "hydro_sign_verify".}

##  ----------------

const
  hydro_kx_SESSIONKEYBYTES* = 32
  hydro_kx_PUBLICKEYBYTES* = 32
  hydro_kx_SECRETKEYBYTES* = 32
  hydro_kx_PSKBYTES* = 32
  hydro_kx_SEEDBYTES* = 32

type
  hydro_kx_keypair* {.bycopy.} = object
    pk*: array[hydro_kx_PUBLICKEYBYTES, uint8]
    sk*: array[hydro_kx_SECRETKEYBYTES, uint8]

  hydro_kx_session_keypair* {.bycopy.} = object
    rx*: array[hydro_kx_SESSIONKEYBYTES, uint8]
    tx*: array[hydro_kx_SESSIONKEYBYTES, uint8]

  hydro_kx_state* {.bycopy.} = object
    eph_kp*: hydro_kx_keypair
    h_st*: hydro_hash_state


proc hydro_kx_keygen*(static_kp: ptr hydro_kx_keypair) {.cdecl,
    importc: "hydro_kx_keygen".}
proc hydro_kx_keygen_deterministic*(static_kp: ptr hydro_kx_keypair;
                                   seed: array[hydro_kx_SEEDBYTES, uint8]) {.
    cdecl, importc: "hydro_kx_keygen_deterministic".}
##  NOISE_N

const
  hydro_kx_N_PACKET1BYTES* = (32 + 16)

proc hydro_kx_n_1*(kp: ptr hydro_kx_session_keypair;
                  packet1: array[hydro_kx_N_PACKET1BYTES, uint8];
                  psk: array[hydro_kx_PSKBYTES, uint8];
                  peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_kx_n_1".}
proc hydro_kx_n_2*(kp: ptr hydro_kx_session_keypair;
                  packet1: array[hydro_kx_N_PACKET1BYTES, uint8];
                  psk: array[hydro_kx_PSKBYTES, uint8];
                  static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_n_2".}
##  NOISE_KK

const
  hydro_kx_KK_PACKET1BYTES* = (32 + 16)
  hydro_kx_KK_PACKET2BYTES* = (32 + 16)

proc hydro_kx_kk_1*(state: ptr hydro_kx_state;
                   packet1: array[hydro_kx_KK_PACKET1BYTES, uint8];
                   peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_kk_1".}
proc hydro_kx_kk_2*(kp: ptr hydro_kx_session_keypair;
                   packet2: array[hydro_kx_KK_PACKET2BYTES, uint8];
                   packet1: array[hydro_kx_KK_PACKET1BYTES, uint8];
                   peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_kk_2".}
proc hydro_kx_kk_3*(state: ptr hydro_kx_state; kp: ptr hydro_kx_session_keypair;
                   packet2: array[hydro_kx_KK_PACKET2BYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_kk_3".}
##  NOISE_XX

const
  hydro_kx_XX_PACKET1BYTES* = (32 + 16)
  hydro_kx_XX_PACKET2BYTES* = (32 + 32 + 16 + 16)
  hydro_kx_XX_PACKET3BYTES* = (32 + 16 + 16)

proc hydro_kx_xx_1*(state: ptr hydro_kx_state;
                   packet1: array[hydro_kx_XX_PACKET1BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8]): cint {.cdecl,
    importc: "hydro_kx_xx_1".}
proc hydro_kx_xx_2*(state: ptr hydro_kx_state;
                   packet2: array[hydro_kx_XX_PACKET2BYTES, uint8];
                   packet1: array[hydro_kx_XX_PACKET1BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_xx_2".}
proc hydro_kx_xx_3*(state: ptr hydro_kx_state; kp: ptr hydro_kx_session_keypair;
                   packet3: array[hydro_kx_XX_PACKET3BYTES, uint8];
                   peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8];
                   packet2: array[hydro_kx_XX_PACKET2BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_xx_3".}
proc hydro_kx_xx_4*(state: ptr hydro_kx_state; kp: ptr hydro_kx_session_keypair;
                   peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8];
                   packet3: array[hydro_kx_XX_PACKET3BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8]): cint {.cdecl,
    importc: "hydro_kx_xx_4".}
##  NOISE_NK

const
  hydro_kx_NK_PACKET1BYTES* = (32 + 16)
  hydro_kx_NK_PACKET2BYTES* = (32 + 16)

proc hydro_kx_nk_1*(state: ptr hydro_kx_state;
                   packet1: array[hydro_kx_NK_PACKET1BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8];
                   peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8]): cint {.
    cdecl, importc: "hydro_kx_nk_1".}
proc hydro_kx_nk_2*(kp: ptr hydro_kx_session_keypair;
                   packet2: array[hydro_kx_NK_PACKET2BYTES, uint8];
                   packet1: array[hydro_kx_NK_PACKET1BYTES, uint8];
                   psk: array[hydro_kx_PSKBYTES, uint8];
                   static_kp: ptr hydro_kx_keypair): cint {.cdecl,
    importc: "hydro_kx_nk_2".}
proc hydro_kx_nk_3*(state: ptr hydro_kx_state; kp: ptr hydro_kx_session_keypair;
                   packet2: array[hydro_kx_NK_PACKET2BYTES, uint8]): cint {.cdecl,
    importc: "hydro_kx_nk_3".}
##  ----------------

const
  hydro_pwhash_CONTEXTBYTES* = 8
  hydro_pwhash_MASTERKEYBYTES* = 32
  hydro_pwhash_STOREDBYTES* = 128

type
  Context* = array[hydro_pwhash_CONTEXTBYTES, char]

proc hydro_pwhash_keygen*(master_key: array[hydro_pwhash_MASTERKEYBYTES, uint8]) {.
    cdecl, importc: "hydro_pwhash_keygen".}
proc hydro_pwhash_deterministic*(h: ptr uint8; h_len: csize_t; passwd: cstring;
                                passwd_len: csize_t;
                                ctx: array[hydro_pwhash_CONTEXTBYTES, char];
    master_key: array[hydro_pwhash_MASTERKEYBYTES, uint8]; opslimit: uint64;
                                memlimit: csize_t; threads: uint8): cint {.cdecl,
    importc: "hydro_pwhash_deterministic".}
proc hydro_pwhash_create*(stored: array[hydro_pwhash_STOREDBYTES, uint8];
                         passwd: cstring; passwd_len: csize_t; master_key: array[
    hydro_pwhash_MASTERKEYBYTES, uint8]; opslimit: uint64; memlimit: csize_t;
                         threads: uint8): cint {.cdecl,
    importc: "hydro_pwhash_create".}
proc hydro_pwhash_verify*(stored: array[hydro_pwhash_STOREDBYTES, uint8];
                         passwd: cstring; passwd_len: csize_t; master_key: array[
    hydro_pwhash_MASTERKEYBYTES, uint8]; opslimit_max: uint64;
                         memlimit_max: csize_t; threads_max: uint8): cint {.cdecl,
    importc: "hydro_pwhash_verify".}
proc hydro_pwhash_derive_static_key*(static_key: ptr uint8;
                                    static_key_len: csize_t; stored: array[
    hydro_pwhash_STOREDBYTES, uint8]; passwd: cstring; passwd_len: csize_t; ctx: array[
    hydro_pwhash_CONTEXTBYTES, char]; master_key: array[
    hydro_pwhash_MASTERKEYBYTES, uint8]; opslimit_max: uint64;
                                    memlimit_max: csize_t; threads_max: uint8): cint {.
    cdecl, importc: "hydro_pwhash_derive_static_key".}
proc hydro_pwhash_reencrypt*(stored: array[hydro_pwhash_STOREDBYTES, uint8];
    master_key: array[hydro_pwhash_MASTERKEYBYTES, uint8]; new_master_key: array[
    hydro_pwhash_MASTERKEYBYTES, uint8]): cint {.cdecl,
    importc: "hydro_pwhash_reencrypt".}
proc hydro_pwhash_upgrade*(stored: array[hydro_pwhash_STOREDBYTES, uint8];
    master_key: array[hydro_pwhash_MASTERKEYBYTES, uint8]; opslimit: uint64;
                          memlimit: csize_t; threads: uint8): cint {.cdecl,
    importc: "hydro_pwhash_upgrade".}
##  ----------------

proc hydro_memzero*(pnt: pointer; len: csize_t) {.cdecl, importc: "hydro_memzero".}
proc hydro_increment*(n: ptr uint8; len: csize_t) {.cdecl, importc: "hydro_increment".}
proc hydro_equal*(b1: pointer; b2: pointer; len: csize_t): bool {.cdecl,
    importc: "hydro_equal".}
proc hydro_compare*(b1: ptr uint8; b2: ptr uint8; len: csize_t): cint {.cdecl,
    importc: "hydro_compare".}
proc hydro_bin2hex*(hex: cstring; hex_maxlen: csize_t; bin: ptr uint8;
                   bin_len: csize_t): cstring {.cdecl, importc: "hydro_bin2hex".}
proc hydro_hex2bin*(bin: ptr uint8; bin_maxlen: csize_t; hex: cstring;
                   hex_len: csize_t; ignore: cstring; hex_end_p: cstringArray): cint {.
    cdecl, importc: "hydro_hex2bin".}
proc hydro_pad*(buf: ptr cuchar; unpadded_buflen: csize_t; blocksize: csize_t;
               max_buflen: csize_t): cint {.cdecl, importc: "hydro_pad".}
proc hydro_unpad*(buf: ptr cuchar; padded_buflen: csize_t; blocksize: csize_t): cint {.
    cdecl, importc: "hydro_unpad".}
##  ----------------

################## High Level wrapper

proc toContext*(str: string): Context =
  assert str.len == hydro_pwhash_CONTEXTBYTES
  copyMem(unsafeAddr result[0], unsafeAddr str[0], hydro_pwhash_CONTEXTBYTES)

var defaultContext* = "12345678".toContext()

### Public-key signatures

proc hydro_sign_create*(msg: string, sk: SecretKey, context = defaultContext): Signature =
  if hydro_sign_create(result, unsafeAddr msg[0], msg.len.csize_t, context, sk) != 0:
    raise newException(ValueError, "hydro_sign_create failed")

proc hydro_sign_verify*(sig: Signature, msg: string, pk: PublicKey, context = defaultContext): bool =
  return hydro_sign_verify(sig, unsafeAddr msg[0], msg.len.csize_t, context, pk) == 0

proc hydro_sign_keygen*(): hydro_sign_keypair =
  hydro_sign_keygen(addr result)


### Secret-key encryption

type
  SecretboxKey* = array[hydro_secretbox_KEYBYTES, uint8]
  MsgId* = uint64

proc hydro_secretbox_keygen*(): SecretboxKey =
  hydro_secretbox_keygen(result)

proc hydro_secretbox_encrypt*(msg: string, key: SecretboxKey, msgId: MsgId = 0,
    context: Context = defaultContext): string =
  let cryptedLen = hydro_secretbox_HEADERBYTES + msg.len
  result = newString(cryptedLen)
  if 0 != hydro_secretbox_encrypt(cast[ptr uint8](addr result[0]), unsafeAddr msg[0], msg.len.csize_t, msgId, context, key):
    raise newException(ValueError, "hydro_secretbox_encrypt failed")

proc hydro_secretbox_decrypt*(crypted: string, key: SecretboxKey, msgId: MsgId = 0,
    context: Context = defaultContext): string =
  let msgLen = crypted.len - hydro_secretbox_HEADERBYTES
  result = newString(msgLen)
  if 0 != hydro_secretbox_decrypt(unsafeAddr result[0], cast[ptr uint8](unsafeAddr crypted[0]), crypted.len.csize_t, msgId, context, key):
    raise newException(ValueError, "hydro_secretbox_decrypt failed")

const
  pskNull*: array[hydro_kx_PSKBYTES, uint8] = default array[hydro_kx_PSKBYTES, uint8]
  contextNull*: array[8, uint8] = default array[8, uint8]

type
  Packet1* = array[hydro_kx_KK_PACKET1BYTES, uint8]
  Packet2* = array[hydro_kx_KK_PACKET2BYTES, uint8]
  # Packet3 = array[hydro_kx_KK_PACKET3BYTES, uint8]

### Generic Hashing
# proc hydro_hash_hash(str: string, len = hydro_hash_BYTES, context = contextNull , psk = pskNull): string = # TODO make context
proc hydro_hash_hash*(str: string, len = hydro_hash_BYTES , psk = pskNull): string =
  result = newString(len)
  var context: array[0..7, char]
  if 0 != hydro_hash_hash(
    cast[ptr uint8](unsafeAddr result[0]),
    hydro_hash_BYTES,
    unsafeAddr str[0],
    str.len.csize_t,
    context, pskNull
  ):
    raise newException(ValueError, "hydro_hash_hash failed")

type
  MasterKey = array[hydro_pwhash_MASTERKEYBYTES, uint8]

proc hydro_pwhash_keygen*(): MasterKey =
  hydro_pwhash_keygen(result)


proc hydro_pwhash_deterministic*(master_key: MasterKey, password: string,
    hashLen: uint, opslimit: uint64, ctx: Context = defaultContext): seq[uint8] =
  result = newSeq[uint8](hashLen)
  if 0 != hydro_pwhash_deterministic(
    h = addr result[0],
    h_len = hashLen.csize_t,
    passwd = unsafeAddr password[0],
    passwd_len = password.len.csize_t,
    ctx = ctx,
    master_key = master_key,
    opslimit = opslimit,
    memlimit = 0, # ignored
    threads = 1, # ignored
  ):
    raise newException(ValueError, "hydro_pwhash_deterministic failed")

### Key exchange

### Helper
proc hydro_bin2hex*[T](bin: T): string =
  let hexLen = (bin.len * 2) + 1
  result = newString(hexLen)
  discard hydro_bin2hex(
    unsafeAddr result[0],
    hexLen.csize_t,
    cast[ptr uint8](unsafeAddr bin),
    bin.len.csize_t
  )

proc hydro_hex2bin*[T](hex: string): T =
  let binLen = (hex.len div 2) + 1 # TODO +1?
  assert T.len == hydro_hex2bin(
    cast[ptr uint8](unsafeAddr result),
    binLen.csize_t,
    unsafeAddr hex[0],
    hex.len.csize_t,
    "", nil
  )

when isMainModule:
  import unittest
  discard hydro_init()
  suite "hydro lowlevel":
    setup:
      var context = "12345678".toContext()
      var msg = "foobaa"

      # # PSK of NULL
      # var pskNull: array[hydro_kx_PSKBYTES, uint8]

    ## TODO Here is an error
    # test "ll hydro_bin2hex / hydro_hex2bin":
    #   # bin_len * 2 + 1
    #   var bin = hydro_sign_keygen().sk
    #   var hexLen = bin.len * 2 + 1
    #   var hex = newString(hexLen)
    #   var hexC = cast[cstring](addr hex[0])
    #   discard hydro_bin2hex(hexC, hexLen.csize_t, cast[ptr uint8](addr bin), bin.len.csize_t)
    #   echo hex

    #   # var binLen = (hex.len div 2) - 1
    #   # var binLen = hex.len # div 2) - 1
    #   var binLen = (hex.len div 2) + 1
    #   # var bin2 = newString(binLen)
    #   var bin2 = alloc(binLen)
    #   echo hydro_hex2bin(cast[ptr uint8](bin2), binLen.csize_t, hexC, hexLen.csize_t, "", nil)
    #   var bin3 = cast[array[hydro_sign_SECRETKEYBYTES, uint8]](addr bin2)
    #   echo bin
    #   echo bin3
    #   check bin == bin3
    #   dealloc(bin2)

    test "hl hydro_bin2hex / hydro_hex2bin":
      var bin = hydro_sign_keygen().sk
      var hex = hydro_bin2hex(bin)
      var bin2 = hydro_hex2bin[array[hydro_sign_SECRETKEYBYTES, uint8]](hex)
      check bin == bin2


    test "ll hydro_sign_create / hydro_sign_verify":
      var kp: hydro_sign_keypair
      hydro_sign_keygen(addr kp)
      var sig: Signature
      check 0 == hydro_sign_create(sig, addr msg[0], msg.len.csize_t, context, kp.sk)
      check 0 == hydro_sign_verify(sig, addr msg[0], msg.len.csize_t, context, kp.pk)

    test "hl hydro_sign_create / hydro_sign_verify":
      var kp = hydro_sign_keygen()
      var sig = hydro_sign_create(msg, kp.sk, context)
      check true == hydro_sign_verify(sig, msg, kp.pk, context)

    test "ll hydro_secretbox_encrypt / hydro_secretbox_decrypt":
      var key: array[hydro_secretbox_KEYBYTES, uint8]
      hydro_secretbox_keygen(key)
      let cryptedLen = hydro_secretbox_HEADERBYTES + msg.len
      var crypted = cast[ptr uint8](alloc(cryptedLen))
      var msgId: uint64 = 1337
      check 0 == hydro_secretbox_encrypt(crypted, addr msg[0], msg.len.csize_t, msgId, context, key)

      var pmsg: pointer = alloc(cryptedLen - hydro_secretbox_HEADERBYTES)
      check 0 == hydro_secretbox_decrypt(pmsg, crypted, cryptedLen.csize_t, msgId, context, key)
      var msg2 = newString(cryptedLen - hydro_secretbox_HEADERBYTES)
      copyMem(addr msg2[0], pmsg, cryptedLen - hydro_secretbox_HEADERBYTES)
      check msg == msg2
      dealloc(crypted)
      dealloc(pmsg)


    test "hl hydro_secretbox_encrypt / hydro_secretbox_decrypt":
      var key = hydro_secretbox_keygen()
      var crypted = hydro_secretbox_encrypt(msg, key)
      var msg2 = hydro_secretbox_decrypt(crypted, key)
      check msg == msg2

    test "ll Generic hashing":
      block:
        var hash = newString(hydro_hash_BYTES)
        check 0 == hydro_hash_hash(cast[ptr uint8](addr hash[0]), hydro_hash_BYTES, addr msg[0], msg.len.csize_t, context, pskNull)
        check hash.len == hydro_hash_BYTES

      block:
        let myLen = 1024
        var hash = newString(myLen)
        check 0 == hydro_hash_hash(cast[ptr uint8](addr hash[0]), csize_t(myLen), addr msg[0], msg.len.csize_t, context, pskNull)
        check hash.len == myLen


    test "hl Generic hashing":
      block:
        let hash = hydro_hash_hash(msg, len = hydro_hash_BYTES)
        check hash.len == hydro_hash_BYTES

      block:
        let myLen = 1024
        let hash = hydro_hash_hash(msg, len = myLen)
        check hash.len == myLen


    test "ll N key exchange variant":
      # - What the client needs to know about the server: the server's public key
      # - What the server needs to know about the client: nothing
      # This variant is designed to anonymously send messages to a recipient using its public key.

      # Server: generate a long-term key pair
      var serverStaticKey: hydro_kx_keypair
      hydro_kx_keygen(addr serverStaticKey)


      # Client: generate session keys and a packet with an ephemeral public key to send to the server
      var packet1: array[hydro_kx_N_PACKET1BYTES, uint8] # this must be sent to the server.
      var sessionKpClient: hydro_kx_session_keypair
      check 0 == hydro_kx_n_1(addr sessionKpClient, packet1, pskNull, serverStaticKey.pk)
      # Done! sessionKpClient.tx is the key for sending data to the server,
      # and sessionKpClient.rx is the key for receiving data from the server.


      # Server: process the initial request from the client, and compute the session keys
      var sessionKpServer: hydro_kx_session_keypair
      check 0 == hydro_kx_n_2(addr sessionKpServer, packet1, pskNull, addr serverStaticKey)
      # Done! sessionKpServer.tx is the key for sending data to the client,
      # and sessionKpServer.rx is the key for receiving data from the client.
      # The session keys are the same as those computed by the client, but swapped.
      check sessionKpClient.tx == sessionKpServer.rx
      check sessionKpClient.rx == sessionKpServer.tx

      # Client sends a secret box to the server
      # the server decrypts it
      block:
        var crypted = hydro_secretbox_encrypt(msg, sessionKpClient.tx) # <- client
        var msg2 = hydro_secretbox_decrypt(crypted, sessionKpServer.rx) # <- server
        check msg == msg2

      # Server sends a secret box to the client
      # the client decrypts it
      block:
        var crypted = hydro_secretbox_encrypt(msg, sessionKpServer.tx) # <- server
        var msg2 = hydro_secretbox_decrypt(crypted, sessionKpClient.rx) # <- client
        check msg == msg2

    # test "hl N key exchange variant": # TODO


    test "ll KK key exchange variant":
      # What the client needs to know about the server: the server's public key
      # What the server needs to know about the client: the client's public key
      # This variant is designed to exchange messages between two parties that already know each other's public key.
      # Client: generate a long-term key pair

      var clientStaticKp: hydro_kx_keypair
      hydro_kx_keygen(addr clientStaticKp)

      # Server: generate a long-term key pair
      var serverStaticKp: hydro_kx_keypair
      hydro_kx_keygen(addr serverStaticKp)

      # Client: initiate a key exchange
      var stClient: hydro_kx_state
      var packet1: Packet1
      check 0 == hydro_kx_kk_1(addr stClient, packet1, serverStaticKp.pk, addr clientStaticKp)

      # Server: process the initial request from the client, and compute the session keys
      var packet2: Packet2
      block:
        var sessionKp: hydro_kx_session_keypair
        check 0 == hydro_kx_kk_2(addr sessionKp, packet2, packet1, clientStaticKp.pk, addr serverStaticKp)
        # Done! sessionKp.tx is the key for sending data to the client,
        # and sessionKp.rx is the key for receiving data from the client.

      # Client: process the server packet and compute the session keys
      block:
        var sessionKp: hydro_kx_session_keypair
        check 0 == hydro_kx_kk_3(addr stClient, addr sessionKp, packet2, addr clientStaticKp)
        # Done! sessionKp.tx is the key for sending data to the server,
        # and sessionKp.rx is the key for receiving data from the server.
        # The session keys are the same as those computed by the server, but swapped.


    test "ll XX key exchange variant":
      # What the client needs to know about the server: nothing
      # What the server needs to know about the client: nothing
      # This is the most versatile variant, but it requires two round trips. In this variant, the client and the server don't need to share any prior data. However, the peers public keys will be exchanged. Discovered public keys can then be discarded, used for authentication, or reused later with the KK variant.

      # Client: generate a long-term key pair
      var client_static_kp: hydro_kx_keypair
      hydro_kx_keygen(addr client_static_kp)

      # Server: generate a long-term key pair
      var server_static_kp: hydro_kx_keypair
      hydro_kx_keygen(addr server_static_kp)

      # Client: initiate a key exchange
      var st_client: hydro_kx_state
      var packet1: array[hydro_kx_XX_PACKET1BYTES, uint8]
      assert 0 == hydro_kx_xx_1(addr st_client, packet1, pskNull); # psk is optional

      # Server: process the initial request from the client
      var st_server: hydro_kx_state
      var packet2: array[hydro_kx_XX_PACKET2BYTES, uint8]
      check 0 == hydro_kx_xx_2(addr st_server, packet2, packet1, pskNull, addr server_static_kp)

      # Client: process the server packet and compute the session keys
      var packet3: array[hydro_kx_XX_PACKET3BYTES, uint8]
      var client_session_kp: hydro_kx_session_keypair
      var client_peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8]
      check 0 == hydro_kx_xx_3(addr st_client, addr client_session_kp,
          packet3, client_peer_static_pk, packet2, pskNull, addr client_static_kp)
      # Done! session_kp.tx is the key for sending data to the server,
      # and session_kp.rx is the key for receiving data from the server.

      # Server: process the client packet and compute the session keys:
      var server_session_kp: hydro_kx_session_keypair
      var server_peer_static_pk: array[hydro_kx_PUBLICKEYBYTES, uint8]
      check 0 == hydro_kx_xx_4(addr st_server, addr server_session_kp, server_peer_static_pk, packet3, pskNull)
      # Done! session_kp.tx is the key for sending data to the client,
      # and session_kp.rx is the key for receiving data from the client.
      # The session keys are the same as those computed by the client, but swapped.



    test "ll hydro_pwhash_keygen":
      var p0: array[hydro_pwhash_MASTERKEYBYTES, uint8]

      var p1: array[hydro_pwhash_MASTERKEYBYTES, uint8]
      hydro_pwhash_keygen(p1)

      var p2: array[hydro_pwhash_MASTERKEYBYTES, uint8]
      hydro_pwhash_keygen(p2)

      check p0 != p1
      check p0 != p2
      check p1 != p2


    test "hl hydro_pwhash_keygen":
      var p0: array[hydro_pwhash_MASTERKEYBYTES, uint8]
      var p1 = hydro_pwhash_keygen()
      var p2 = hydro_pwhash_keygen()
      check p0 != p1
      check p0 != p2
      check p1 != p2

    test "ll hydro_pwhash_deterministic":
      let master_key = hydro_pwhash_keygen()
      let CONTEXT = "Examples".toContext()
      let OPSLIMIT = 10000.uint64
      let MEMLIMIT = 0.csize_t
      let THREADS =  1.uint8
      let PASSWORD = "test"
      let PASSWORD_LEN = 4.csize_t
      var derived_key_null: array[32, uint8];
      var derived_key_1: array[32, uint8];
      var derived_key_2: array[32, uint8];
      check 0 == hydro_pwhash_deterministic(addr derived_key_1[0], sizeof(derived_key_1).csize_t, PASSWORD, PASSWORD_LEN,
                                CONTEXT, master_key, OPSLIMIT, MEMLIMIT, THREADS);
      check 0 == hydro_pwhash_deterministic(addr derived_key_2[0], sizeof(derived_key_2).csize_t, PASSWORD, PASSWORD_LEN,
                                CONTEXT, master_key, OPSLIMIT, MEMLIMIT, THREADS);
      check derived_key_null != derived_key_1
      check derived_key_null != derived_key_2
      check derived_key_1 == derived_key_2

      # change the master key and test if derived keys are different
      let master_key2 = hydro_pwhash_keygen()
      var derived_key_m2_1: array[32, uint8];
      var derived_key_m2_2: array[32, uint8];
      check 0 == hydro_pwhash_deterministic(addr derived_key_m2_1[0], sizeof(derived_key_1).csize_t, PASSWORD, PASSWORD_LEN,
                                CONTEXT, master_key2, OPSLIMIT, MEMLIMIT, THREADS);
      check 0 == hydro_pwhash_deterministic(addr derived_key_m2_2[0], sizeof(derived_key_2).csize_t, PASSWORD, PASSWORD_LEN,
                                CONTEXT, master_key2, OPSLIMIT, MEMLIMIT, THREADS);
      check derived_key_m2_1 != derived_key_1
      check derived_key_m2_2 != derived_key_2
      check derived_key_m2_1 == derived_key_m2_2


    # test "hl hydro_pwhash_deterministic":
    #   discard
    #   raise

    test "ll hydro_pwhash_create":
      let masterKey = hydro_pwhash_keygen()
      var pwhash: array[hydro_pwhash_STOREDBYTES, uint8]
      var passwd = "p4ssw0rd"
      var opslimit = 10.uint64 # <- choose a higher value for production!
      var memlimit = 0.csize_t
      var threads = 1.uint8
      check 0 == hydro_pwhash_create(
        stored = pwhash,
        passwd = addr passwd[0],
        passwd_len = passwd.len().csize_t,
        master_key = masterKey,
        opslimit = opslimit,
        memlimit = memlimit,
        threads = threads
      )





# DOES NOT WORK.
# import ed25519
# var secret = newString(32)
# var clientStaticKp: hydro_kx_keypair
# hydro_kx_keygen(addr clientStaticKp)

# # Server: generate a long-term key pair
# var serverStaticKp: hydro_kx_keypair
# hydro_kx_keygen(addr serverStaticKp)

# var both1: array[64, uint8]
# copyMem(addr both1[0], addr serverStaticKp.pk, 32)
# copyMem(addr both1[31], addr serverStaticKp.sk, 32)
# echo keyExchange(clientStaticKp.pk, both1)

# var both2: array[64, uint8]
# copyMem(addr both2[0], addr clientStaticKp.pk, 32)
# copyMem(addr both2[31], addr clientStaticKp.sk, 32)
# echo keyExchange(serverStaticKp.pk, both2)
