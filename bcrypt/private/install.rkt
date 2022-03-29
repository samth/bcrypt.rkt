#lang racket/base

(require racket/file
         dynext/file
         dynext/link
         setup/dirs)

(provide pre-installer)

(define SOURCEDIR "crypt_blowfish-1.2")

(define (pre-installer collections-top-path this-collection-path user-specific?)
  (define private-path (build-path this-collection-path "private"))

  (parameterize ((current-directory private-path))
    (define unpacked-path (build-path private-path SOURCEDIR))
    (define lib-path (if user-specific? (find-user-lib-dir) (find-lib-dir)))
    (define shared-object-target
      (build-path lib-path
                  (append-extension-suffix "libcrypt_blowfish")))

    (make-directory* lib-path)
    (when (file-exists? shared-object-target) (delete-file shared-object-target))
    (define c-sources
      (for/list ((c (list "crypt_blowfish.c"
                          "crypt_gensalt.c"
                          "wrapper.c")))
        (build-path unpacked-path c)))

    (parameterize ((current-extension-linker-flags
                    (append (current-extension-linker-flags)
                            (list "-O2" "-fomit-frame-pointer" "-funroll-loops"
                                  "-DNO_BF_ASM"
                                  "-I" (path->string unpacked-path))))
                   [current-use-mzdyn #f])
      (link-extension #f ;; not quiet
                      c-sources
                      shared-object-target))))
