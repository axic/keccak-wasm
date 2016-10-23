;;
;; Keccak testing module
;; Exports a memory block, the first 32 bytes are used as the input to SHA3-256
;; and the output offset will be returned.
;;
;; input (136 bytes of zeroes): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
;; output (keccak-256): 3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9
;;
(module
  (memory 1)

  (export "memory" memory)
  (export "keccak" 0)
  (func
    (result i32)
    (block
      (call $keccak (i32.const 168) (i32.const 0) (i32.const 136) (i32.const 136))
      (return (i32.const 136))
      (unreachable)
    )
  )

;;
;; memcpy from ewasm-libc/ewasm-cleanup
;;
(func $memcpy
  (param $dst i32)
  (param $src i32)
  (param $length i32)
  (result i32)

  (local $i i32)

  (set_local $i (i32.const 0))

  (loop $done $loop
    (if (i32.ge_u (get_local $i) (get_local $length))
      (br $done)
    )

    (i32.store8 (i32.add (get_local $dst) (get_local $i)) (i32.load8_u (i32.add (get_local $src) (get_local $i))))

    (set_local $i (i32.add (get_local $i) (i32.const 1)))
    (br $loop)
  )

  (return (get_local $dst))
)

(func $memset
  (param $ptr i32)
  (param $value i32)
  (param $length i32)
  (result i32)

  (local $i i32)

  (set_local $i (i32.const 0))

  (loop $done $loop
    (if (i32.ge_u (get_local $i) (get_local $length))
      (br $done)
    )

    (i32.store8 (i32.add (get_local $ptr) (get_local $i)) (get_local $value))

    (set_local $i (i32.add (get_local $i) (i32.const 1)))
    (br $loop)
  )

  (return (get_local $ptr))
)

)
