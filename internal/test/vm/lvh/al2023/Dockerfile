# Extract vmlinuz + modules from an Amazon Linux 2023 kernel RPM.
# Consumed by run.sh via `docker buildx build --output type=local`.
# Build: --build-arg KERNEL_NVR=<version>-<release>.amzn2023
#        --build-arg KERNEL_PKG=<kernel | kernel6.12 | ...>
ARG KERNEL_NVR
ARG KERNEL_PKG=kernel

FROM amazonlinux:2023@sha256:267b42d61c8eb5537270b62ec97b73bb104708d9245d343b5eeb1d92f0f65d3d AS extract
ARG KERNEL_NVR
ARG KERNEL_PKG
ARG TARGETARCH

RUN dnf install -y --setopt=install_weak_deps=False cpio findutils && dnf clean all

WORKDIR /work

# Download kernel + modules-extra RPMs without installing, then unpack and
# re-layout into /data/kernels/<KREL>/{boot,lib/modules} for the consumer.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) RPM_ARCH=x86_64 ;; \
        arm64) RPM_ARCH=aarch64 ;; \
        *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    dnf install -y --downloadonly --downloaddir=/work \
        "${KERNEL_PKG}-${KERNEL_NVR}.${RPM_ARCH}" \
        "${KERNEL_PKG}-modules-extra-${KERNEL_NVR}.${RPM_ARCH}"; \
    mkdir -p /work/extracted; cd /work/extracted; \
    for rpm in /work/*.rpm; do rpm2cpio "$rpm" | cpio -idm 2>/dev/null; done; \
    KREL="$(ls /work/extracted/lib/modules | head -1)"; \
    [ -n "$KREL" ] || { echo "no kernel modules dir found" >&2; exit 1; }; \
    mkdir -p "/data/kernels/${KREL}/boot" "/data/kernels/${KREL}/lib/modules"; \
    cp "/work/extracted/lib/modules/${KREL}/vmlinuz" \
       "/data/kernels/${KREL}/boot/vmlinuz-${KREL}" 2>/dev/null \
      || cp "/work/extracted/boot/vmlinuz-${KREL}" \
            "/data/kernels/${KREL}/boot/vmlinuz-${KREL}"; \
    cp -a "/work/extracted/lib/modules/${KREL}" \
          "/data/kernels/${KREL}/lib/modules/${KREL}"

FROM scratch
COPY --from=extract /data /data
