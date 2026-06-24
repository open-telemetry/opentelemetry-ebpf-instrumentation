FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS goimage

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

# Import the Go toolchain from the pinned golang image while keeping Alpine as runtime base.
COPY --from=goimage /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# Track the latest Alpine instead of pinning to 3.20. The 3.20 pin worked
# around newer runc's procfs hardening ("unsafe procfs detected") failing in
# the nested-VM CI; that no longer reproduces on the current runner. See #872.
RUN apk update && apk add --no-cache \
    agetty \
    bash \
    ca-certificates \
    docker \
    docker-cli-compose \
    git \
    iptables \
    iptables-legacy \
    make \
    openrc

# Default iptables symlink to legacy; modules-load may relink to nft on
# RHEL kernels that lack CONFIG_IP_NF_NAT modules.
RUN for t in iptables ip6tables; do \
        ln -sf "$(command -v ${t}-legacy)" "$(command -v ${t})"; \
    done

# Module-load service: LVH kernels ship loadable modules for overlayfs,
# br_netfilter, nf_tables, etc. Runs before localmount because /etc/fstab
# mounts /build (overlay) and Docker needs br_netfilter.
RUN cat <<'EOF' > /etc/init.d/modules-load
#!/sbin/openrc-run
description="Mount kernel modules over 9p (if available) and load Docker/overlay deps"

depend() {
    need sysfs
    before localmount
}

start() {
    ebegin "Loading kernel modules"
    KREL="$(uname -r)"
    mkdir -p "/lib/modules/${KREL}"
    # Always (re)mount the 9p modules tree. The mountpoint dir persists
    # in the rootfs across boots, so checking [ -d ] is unsafe — the dir
    # may exist but be empty if the 9p tag isn't supplied this boot.
    if mountpoint -q "/lib/modules/${KREL}" 2>/dev/null; then
        einfo "/lib/modules/${KREL} already mounted"
    elif mount -t 9p -o ro,trans=virtio,version=9p2000.L,msize=524288 modules "/lib/modules/${KREL}" 2>/dev/null; then
        einfo "mounted /lib/modules/${KREL} from 9p"
    else
        einfo "no modules 9p tag; assuming monolithic kernel"
    fi
    # depmod refreshes modules.dep but the 9p mount is RO, so the rewrite
    # silently no-ops; LVH images already ship a complete modules.dep.
    depmod -a "${KREL}" 2>/dev/null || true
    # Modules common to both stacks.
    failed=""
    for m in overlay br_netfilter ip_tables xt_addrtype xt_conntrack \
             nf_conntrack vxlan macvlan veth; do
        if ! modprobe "$m" 2>/dev/null; then
            failed="${failed} ${m}"
        fi
    done
    if [ -n "$failed" ]; then
        ewarn "modprobe failed for:${failed}"
    fi
    # overlay is critical: /etc/fstab mounts /build over it next. Surface
    # explicit failure rather than letting localmount fail opaquely.
    if ! grep -qw overlay /proc/filesystems && ! grep -qw overlay /proc/modules; then
        eend 1 "overlay module not loaded; check /lib/modules/${KREL} contents"
        return 1
    fi
    # Repoint the iptables/ip6tables CLI docker shells out to. Resolve the
    # binary docker actually runs (Alpine 3.21+ keeps these in /usr/sbin, not
    # /sbin) instead of hardcoding a directory, so a missing variant yields a
    # no-op rather than a dangling link that leaves docker on the wrong backend.
    set_ipt_backend() {
        for t in iptables ip6tables; do
            target="$(command -v "${t}-$1" 2>/dev/null)" || continue
            link="$(command -v "$t" 2>/dev/null)" || link="/usr/sbin/$t"
            ln -sf "$target" "$link"
        done
    }
    # Pick iptables backend at runtime. xt_nat (DNAT/SNAT target) doesn't
    # autoload on RHEL kernels so we modprobe it explicitly; if missing,
    # fall through to the nft branch.
    if modprobe iptable_nat 2>/dev/null && modprobe iptable_filter 2>/dev/null \
        && modprobe xt_nat 2>/dev/null; then
        modprobe xt_MASQUERADE 2>/dev/null || true
        modprobe xt_REDIRECT 2>/dev/null || true
        modprobe nf_nat 2>/dev/null || true
        modprobe iptable_raw 2>/dev/null || true
        set_ipt_backend legacy
        einfo "iptables backend: legacy"
    elif modprobe nf_tables 2>/dev/null \
        && modprobe nft_compat 2>/dev/null \
        && modprobe nft_chain_nat 2>/dev/null; then
        modprobe nft_masq 2>/dev/null || true
        modprobe nf_nat 2>/dev/null || true
        set_ipt_backend nft
        einfo "iptables backend: nft"
    else
        ewarn "neither legacy nor nft NAT modules available; docker NAT will fail"
    fi
    # bpffs at /sys/fs/bpf: required by log enricher + profile correlation
    # pinned maps. Alpine OpenRC doesn't auto-mount it.
    mkdir -p /sys/fs/bpf
    if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
        mount -t bpf bpffs /sys/fs/bpf || ewarn "bpffs mount failed"
    fi
    eend 0
}
EOF

RUN chmod +x /etc/init.d/modules-load && \
    rc-update add modules-load boot && \
    rc-update add localmount default && \
    rc-update add docker default && \
    echo ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100 >> /etc/inittab && \
    mkdir -p /overlay/upper/testoutput /overlay/work /build /obi

# msize=524288: the default 9p block size (8192) silently truncates large
# reads (e.g. go.sum ~100KB), surfacing as "malformed go.sum: wrong number
# of fields". QEMU prints a warning when the client picks <= 8192.
RUN cat <<EOF >> /etc/fstab
obi          /obi               9p      trans=virtio,version=9p2000.L,msize=524288                     0  0
overlay      /build             overlay lowerdir=/obi,upperdir=/overlay/upper,workdir=/overlay/work  0  0
tmpfs        /tmp               tmpfs   rw,nodev,nosuid                                                0  0
devpts       /dev/pts           devpts  defaults                                                       0  0
tmpfs        /run               tmpfs   defaults,size=4G                                               0  0
testout      /build/testoutput  9p      trans=virtio,version=9p2000.L,msize=524288                     0  0
precompiled  /precompiled-tests 9p      trans=virtio,version=9p2000.L,msize=524288                     0  0
EOF

RUN echo obi > /etc/hostname

RUN cat <<EOF > /etc/network/interfaces
auto eth0
iface eth0 inet dhcp

auto lo
iface lo inet loopback
EOF

RUN rc-update add networking default

RUN cat <<'EOF' > /etc/init.d/startup
#!/sbin/openrc-run
description="Run test target then power off"

depend() {
    need docker
    after localmount
}

start() {
    ebegin "Running test startup"
    sh /startup.sh
    eend $?
}
EOF

RUN chmod +x /etc/init.d/startup

# comment out this line to get a prompt instead
# of running the tests when the VM starts
RUN rc-update add startup default

RUN cat <<'EOF' > /startup.sh
#!/bin/sh

export PATH=$PATH:/usr/local/go/bin
export HOME=/root
# Use /build (overlay-backed, ~20G) rather than tmpfs /tmp for Go's build
# cache and tempdir. The Go toolchain writes hundreds of MB per build (vet
# cfgs, importcfgs, intermediate objects), which exhausts the default
# tmpfs allotment on a 2GB-RAM VM and breaks `run-bpf-verifier-vm`.
export GOCACHE=/build/gocache
export TMPDIR=/build/tmp
mkdir -p "$HOME" "$GOCACHE" "$TMPDIR"
git config --global --add safe.directory /build

echo "--- mount state ---"
mount | grep -E "cgroup|sys/fs" || true
iptables --version 2>&1 | head -1 || true

DOCKER_WAIT_MAX=60
i=0
while ! docker info >/dev/null 2>&1; do
    i=$((i + 1))
    if [ $i -ge $DOCKER_WAIT_MAX ]; then
        echo "ERROR: dockerd did not become ready within ${DOCKER_WAIT_MAX}s" >&2
        echo "--- /var/log/docker.log ---" >&2
        [ -f /var/log/docker.log ] && tail -100 /var/log/docker.log >&2
        echo "--- /var/log/messages (last 50) ---" >&2
        [ -f /var/log/messages ] && tail -50 /var/log/messages >&2
        echo "--- dockerd service status ---" >&2
        rc-service docker status >&2 2>&1 || true
        echo "--- kernel ring buffer (last 50) ---" >&2
        dmesg | tail -50 >&2 2>&1 || true
        poweroff
        exit 1
    fi
    echo "Waiting for Docker daemon to start... ($i/${DOCKER_WAIT_MAX})"
    sleep 1
done
echo "Docker daemon is ready"

# panic_on_rcu_stall surfaces hangs as test failures for integration runs.
# Skip it for the verifier suite: a heavy verifier load can hold a CPU long
# enough to trip the stall detector even though it's making progress.
case "$(cat /build/testoutput/test-env 2>/dev/null | grep '^target=' | cut -d= -f2)" in
    run-bpf-verifier-vm)
        echo "skipping panic_on_rcu_stall (verifier suite)"
        ;;
    *)
        sysctl -w kernel.panic_on_rcu_stall=1 2>/dev/null || true
        ;;
esac

echo "=== Docker/runc versions in VM ==="
docker version
runc --version
echo "=================================="

target=""
test_pattern=""
run_number=""
if [ -r /build/testoutput/test-env ]; then
    while IFS='=' read -r k v; do
        case "$k" in
            target) target="$v" ;;
            test_pattern) test_pattern="$v" ;;
            run_number) run_number="$v" ;;
        esac
    done < /build/testoutput/test-env
fi

if [ -n "$target" ]; then
    echo "=== Starting test execution ==="
    if [ -n "$test_pattern" ] && [ "$target" = "run-integration-test-vm" ]; then
        echo "Target: $target  Pattern: $test_pattern  Run: $run_number"
    else
        echo "Target: $target  Run: $run_number"
    fi
    export TEST_PROJECT_DIR=/build

    if [ -f "/precompiled-tests/docker-images.tar" ]; then
        echo "Loading pre-built Docker images..."
        docker load -i /precompiled-tests/docker-images.tar
        export SKIP_DOCKER_BUILD=1
    fi

    # Pre-pulled base images for services that still auto-build in the VM.
    if [ -f "/precompiled-tests/base-images.tar" ]; then
        echo "Loading pre-pulled base images..."
        docker load -i /precompiled-tests/base-images.tar
    fi

    cd /build && make $target TEST_PATTERN="$test_pattern" RUN_NUMBER="$run_number" && touch /build/testoutput/success
    poweroff
else
    echo "Entering interactive mode (no /build/testoutput/test-env)"
fi
EOF

RUN chmod +x /startup.sh
