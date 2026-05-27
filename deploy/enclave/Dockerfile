# Confidential router enclave image: nitriding (RA-TLS + attestation + tap0) launching
# the enclave-core data plane as its -appwebsrv app.
#
# alpine is pinned by digest so PCR0 is reproducible ([NEEDS-EVIDENCE #1]); update the
# digest deliberately and re-publish PCR0 when bumping the base. (alpine:3.20, 2026-05-27)
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

COPY nitriding /bin/nitriding
COPY enclave-core /bin/enclave-core

# nitriding terminates client RA-TLS on :443, proxies every non-/enclave* path to the
# enclave-core HTTP app on 127.0.0.1:8081, bridges to the host gvproxy over vsock 1024, and
# holds the public listener until enclave-core signals GET 127.0.0.1:8080/enclave/ready.
CMD ["/bin/nitriding", \
  "-fqdn", "router.local", \
  "-appwebsrv", "http://127.0.0.1:8081", \
  "-intport", "8080", \
  "-ext-pub-port", "443", \
  "-host-proxy-port", "1024", \
  "-wait-for-app", \
  "-appcmd", "/bin/enclave-core"]
