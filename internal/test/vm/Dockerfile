FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS goimage

FROM alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805

# Import the Go toolchain from the pinned golang image while keeping Alpine as runtime base.
COPY --from=goimage /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# this is the toplevel Makefile target to be invoked
# see the contents of 'startup.sh' at the end of this file
ARG target=run-integration-test-vm
ARG test_pattern=TestMultiProcess
ARG run_number=1

# Install Docker/runc from the pinned Alpine 3.20 base image
# The procfs security checks in newer runc (CVE-2025-52881, CVE-2025-52565,
# CVE-2025-31133) prevent containers from starting in nested virtualization.
# Even buildkit containers fail to boot, so insecure buildx approach is not viable.
RUN apk update && apk add --no-cache \
    agetty \
    bash \
    ca-certificates \
    docker \
    docker-cli-compose \
    git \
    make \
    openrc \
    openssh \
    shadow

RUN ssh-keygen -A && \
    echo "root:root" | chpasswd && \
    sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    rc-update add localmount default && \
    rc-update add docker default && \
    rc-update add sshd default && \
    echo ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100 >> /etc/inittab && \
    mkdir -p /overlay/upper/testoutput /overlay/work /build /obi

RUN cat <<EOF >> /etc/fstab
obi          /obi               9p      trans=virtio,version=9p2000.L                                  0  0
overlay      /build             overlay lowerdir=/obi,upperdir=/overlay/upper,workdir=/overlay/work  0  0
tmpfs        /tmp               tmpfs   rw,nodev,nosuid                                                0  0
devpts       /dev/pts           devpts  defaults                                                       0  0
tmpfs        /run               tmpfs   defaults,size=4G                                               0  0
testout      /build/testoutput  9p      trans=virtio,version=9p2000.L                                  0  0
precompiled  /precompiled-tests 9p      trans=virtio,version=9p2000.L                                  0  0
EOF

RUN echo obi > /etc/hostname

RUN cat <<EOF > /etc/network/interfaces
auto eth0
iface eth0 inet dhcp

auto lo
iface lo inet loopback
EOF

RUN rc-update add networking default

RUN cat <<EOF > /etc/init.d/startup
#!/sbin/openrc-run

command="sh /startup.sh"
EOF

RUN chmod +x /etc/init.d/startup

# comment out this line to get a prompt instead
# of running the tests when the VM starts
RUN rc-update add startup default

RUN cat <<EOF > /startup.sh
#!/bin/sh

export PATH=$PATH:/usr/local/go/bin

# Fix Git ownership issues
git config --global --add safe.directory /build

# Wait for Docker service to be ready
while ! docker info >/dev/null 2>&1; do
    echo "Waiting for Docker daemon to start..."
    sleep 1
done
echo "Docker daemon is ready"

# Panic immediately on RCU CPU stalls instead of hanging for the full
# job timeout. Combined with 'panic' boot param and QEMU -no-reboot,
# this causes QEMU to exit after the first stall.
sysctl -w kernel.panic_on_rcu_stall=1 2>/dev/null || true

# Verify runc version
echo "=== Docker/runc versions in VM ==="
docker version
runc --version
echo "=================================="

if [[ -n "$target" ]]; then
    echo "=== Starting test execution ==="
    echo "Current directory: $(pwd)"
    
    # Set project directory for pre-compiled binaries
    export TEST_PROJECT_DIR=/build
    
    # Load pre-built Docker images if available (built on host at native speed)
    if [ -f "/precompiled-tests/docker-images.tar" ]; then
        echo "Loading pre-built Docker images..."
        docker load -i /precompiled-tests/docker-images.tar
        echo "Pre-built Docker images loaded:"
        docker images --format "  {{.Repository}}:{{.Tag}} ({{.Size}})"
        export SKIP_DOCKER_BUILD=1
    fi
    
    cd /build && make $target TEST_PATTERN="$test_pattern" RUN_NUMBER="$run_number" && touch /build/testoutput/success
    poweroff
else
    echo "Entering interactive mode"
fi
EOF

RUN chmod +x /startup.sh
