(use-modules (guix)
             (guix build-system go)
             (guix licenses)

             (gnu packages golang)
             (gnu packages security-token)
             (gnu packages tls))

(package
 (name "openconnect-gp-okta")
 (version "0.1.0")
 (source
  (origin
   (method url-fetch)
   (uri (format #f "file://~a" (getcwd)))
   (sha256
    (base32 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))))
 (build-system go-build-system)
 (arguments
  `(#:go ,go-1.20
    #:import-path "openconnect-gp-okta"))
 (inputs (list libfido2 libressl))
 (synopsis "@code{openconnect} wrapper which performs a webauthn flow")
 (description
  "@code{openconnect-gp-okta} first performs a webauthn flow against a
GlobalProtect VPN endpoint which uses Okta and an authentication device. It then
launches @code{openconnect} and passes the pre-login cookie obtained to it.")
 (home-page "http://katherine.cox-buday.com")
 (license gpl3+))
