# wash-web image. Build the static binary first: `make image` does both.
# Dev/fast path only; production uses Containerfile.build via the quadlet.
FROM scratch
COPY bin/wash-web /wash-web
# scratch has no users or dirs: run unprivileged, data on a volume
USER 65532:65532
VOLUME /var/lib/wash
ENV WASH_DATA=/var/lib/wash WASH_LISTEN=0.0.0.0:8443 HOME=/var/lib/wash TMPDIR=/var/lib/wash
EXPOSE 8443
ENTRYPOINT ["/wash-web"]
CMD ["serve"]
