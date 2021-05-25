#lang racket/base

(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/define
         racket/runtime-path)
(provide encode check match)

(define-runtime-path libcrypt_blowfish
  '(so "libcrypt_blowfish"))

(define-ffi-definer define-crypt
  (ffi-lib libcrypt_blowfish))

;; These constants taken directly from the source
(define CRYPT_OUTPUT_SIZE		(+ 7 22 31 1))
(define CRYPT_GENSALT_OUTPUT_SIZE	(+ 7 22 1))

(define-crypt crypt_rn (_fun _bytes/nul-terminated _bytes
                             (out : (_bytes o CRYPT_OUTPUT_SIZE))
                             (_int = CRYPT_OUTPUT_SIZE)
                             -> (r : _int)
                             -> (if (zero? r) #f out)))

(define-crypt crypt_gensalt_rn (_fun _bytes/nul-terminated _long (salt : _bytes)
                                     (_int = (bytes-length salt))
                                     (out : (_bytes o CRYPT_GENSALT_OUTPUT_SIZE))
                                     (_int = CRYPT_GENSALT_OUTPUT_SIZE)
                                     -> (r : _int)
                                     -> (if (zero? r) #f out)))

;; 2y indicates that this doesn't have the 8-bit bug
(define PREFIX #"$2y$")
(define _rounds 12)

;; we accept both a and y prefixes
(define bcrypt-re #px#"\\$2[ay]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}")

;; get n random bits from /dev/urandom
(define (urandom n)
  (unless (file-exists? "/dev/urandom")
    (error 'bcrypt "/dev/urandom needed for random seed generation"))
  (with-input-from-file "/dev/urandom"
    (lambda () (read-bytes n))))

(define (encode bs #:rounds [rounds _rounds])
  (define settings (crypt_gensalt_rn PREFIX rounds (urandom 16)))
  (unless settings (error 'encode "crypt_gensalt_rn failure"))
  (define result (crypt_rn bs settings))
  (unless result (error 'encode "crypt_rn failure"))
  result)


(define (check encoded bs)
  (unless (match encoded)
    (error 'check "invalid encoded input"))
  (define new (crypt_rn bs encoded))
  (unless new (error 'check "crypt_rn failure"))
  (equal? new encoded))

(define (match bs) (regexp-match bcrypt-re bs))

(module+ test
         (require (except-in rackunit check))

         (define encoded (encode #"foo"))
         (check-true (check encoded #"foo"))
         (check-false (check encoded #"fooo")))
