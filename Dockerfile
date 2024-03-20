FROM aquasec/trivy:latest AS trivy

FROM alpine:3
RUN apk update && apk upgrade && apk --no-cache add bash curl jq util-linux skopeo file tar
COPY --from=trivy /contrib /contrib
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN addgroup -g 65532 -S nonroot \
  && adduser -u 65532 -S nonroot -G nonroot -s /bin/sh

WORKDIR /home/nonroot
COPY scan.sh \
     scan-date.sh \
     scan-download-unpack.sh \
     scan-inthewild-io.sh \
     scan-misconfig.sh \
     scan-new-tags.sh \
     scan-trivy.sh \
     scan-virustotal.sh \
     scan-vulners-com.sh \
     ./
RUN chown -R 65532:65532 *.sh && chmod -R 755 *.sh

USER nonroot
