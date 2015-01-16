#lang racket/base

(require racket/system)
(require racket/file)
(require dynext/file)
(require dynext/link)

(require file/untgz)

(provide pre-installer)

(define SOURCEDIR "crypt_blowfish-1.2")

(define (pre-installer collections-top-path this-collection-path)
  (define private-path (build-path this-collection-path "private"))

  (parameterize ((current-directory private-path))
    (define unpacked-path (build-path private-path SOURCEDIR))
    (define shared-object-target-path (build-path private-path
						  "compiled"
						  "native"
						  (system-library-subpath)))
    (define shared-object-target (build-path shared-object-target-path
					     (append-extension-suffix "libcrypt_blowfish")))

    (when (file-exists? shared-object-target) (delete-file shared-object-target))
    (define c-sources
      (for/list ((c (list "crypt_blowfish.c"
                          "crypt_gensalt.c"
                          "wrapper.c")))
        (build-path unpacked-path c)))

    (make-directory* shared-object-target-path)
    (parameterize ((current-extension-linker-flags
                    (append (current-extension-linker-flags)
                            (list "-O2" "-fomit-frame-pointer" "-funroll-loops"
                                  "-DNO_BF_ASM"
                                  "-I" (path->string unpacked-path)
                                  ))))
      (link-extension #f ;; not quiet
                      c-sources
                      shared-object-target))))
