FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# a uniquely-named shell binary so OBI can target it via executable-path discovery
RUN cp /bin/dash /substsh

COPY internal/test/integration/components/shellsubst/subst_loop.sh /subst_loop.sh

ENTRYPOINT ["/substsh", "/subst_loop.sh"]
