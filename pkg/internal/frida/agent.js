// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const maxRequest = 1024 * 1024;
const maxHeaders = 8192;
const minWriteFragment = 512;
const responseStatusPrefix = 12;
const sslMode = {control: 33, partialWrite: 1, movingBuffer: 2};
const addressFamily = {ipv4: 2, ipv6: 10};
const ipv4MappedPrefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255];
// These offsets match frida_request_t, connection_info_t, and frida_payload_t.
const abi = {
    context: {command: 0x0b10f1, size: 104, connection: 8, traceparent: 44, ready: 99},
    connection: {size: 36, peer: 16, localPort: 32, peerPort: 34},
    payload: {command: 0x0b10f2, size: 56, length: 36, buffer: 40, direction: 48},
};
const pending = new Map();
const depth = new Map();
const hooks = new Map();
const installed = [];
let observer = null;
const traceparentLength = 55;
const headerLength = 'traceparent: '.length + traceparentLength + 2;
let enabled = false;
const failures = [];
let ioctl = null;
let inetPton = null;
const responsePrefixes = new Map();
const awaitingResponse = new Set();

function contextRequest(buffer, cancel = false, connection = null) {
    const request = Memory.alloc(abi.context.size);
    request.writePointer(buffer);
    if (connection !== null) {
        Memory.copy(request.add(abi.context.connection), connection, abi.connection.size);
    }
    request.add(abi.context.ready).writeU8(cancel ? 2 : 0);
    ioctl(0, abi.context.command, request);
    return request.add(abi.context.ready).readU8() === 1 ? request.add(abi.context.traceparent).readUtf8String(traceparentLength) : null;
}

function connectionFor(ssl, getFD) {
    const fd = getFD(ssl);
    const local = Socket.localAddress(fd);
    const peer = Socket.peerAddress(fd);
    if (local === null || peer === null || !local.ip || !peer.ip) {
        return null;
    }
    const connection = Memory.alloc(abi.connection.size);
    for (const [address, offset] of [[local, 0], [peer, abi.connection.peer]]) {
        const ipv4 = address.ip.indexOf(':') < 0;
        const destination = connection.add(offset);
        if (ipv4) {
            destination.writeByteArray(ipv4MappedPrefix);
        }
        if (inetPton(ipv4 ? addressFamily.ipv4 : addressFamily.ipv6, Memory.allocUtf8String(address.ip),
                     destination.add(ipv4 ? ipv4MappedPrefix.length : 0)) !== 1) {
            return null;
        }
    }
    connection.add(abi.connection.localPort).writeU16(local.port);
    connection.add(abi.connection.peerPort).writeU16(peer.port);
    return connection;
}

function report(ssl, connection, buffer, length, direction) {
    if (connection === null || length <= 0 || length > maxRequest) {
        return;
    }
    if (direction === 'read' && awaitingResponse.has(ssl)) {
        const previous = responsePrefixes.get(ssl);
        if (previous) {
            const combined = Memory.alloc(previous.length + length);
            Memory.copy(combined, previous.buffer, previous.length);
            Memory.copy(combined.add(previous.length), buffer, length);
            length += previous.length;
            buffer = combined;
            responsePrefixes.delete(ssl);
        }
        if (length < responseStatusPrefix) {
            const prefix = String.fromCharCode(...new Uint8Array(buffer.readByteArray(Math.min(length, 5))));
            if ('HTTP/'.startsWith(prefix)) {
                const copy = Memory.alloc(length);
                Memory.copy(copy, buffer, length);
                responsePrefixes.set(ssl, {buffer: copy, length});
                return;
            }
        }
        awaitingResponse.delete(ssl);
    }
    const request = Memory.alloc(abi.payload.size);
    Memory.copy(request, connection, abi.connection.size);
    request.add(abi.payload.length).writeU32(length);
    request.add(abi.payload.buffer).writePointer(buffer);
    request.add(abi.payload.direction).writeU8(direction === 'write' ? 1 : 0);
    ioctl(0, abi.payload.command, request);
}

function readSize(address) {
    return address.readU64().toNumber();
}

function writeSize(address, value) {
    address.writeU64(value);
}

function originalOffset(state, wireOffset) {
    if (wireOffset <= state.insertAt) {
        return wireOffset;
    }
    return wireOffset - Math.min(wireOffset - state.insertAt, headerLength);
}

function replacement(ssl, sslPointer, buffer, requested, connection, control, text) {
    if (!enabled || pending.size >= 256 || requested <= 0 || requested > maxRequest - headerLength) {
        return null;
    }
    if (text === null || !/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^ \r\n]+ HTTP\/1\.1\r\n/.test(text)) {
        return null;
    }
    const end = text.indexOf('\r\n\r\n');
    if (end < 0 || /(?:^|\r\n)(?:traceparent|upgrade)\s*:/i.test(text.slice(0, end))) {
        return null;
    }

    const insertAt = end + 2;
    const mode = Number(control(sslPointer, sslMode.control, 0, NULL));
    if ((mode & sslMode.partialWrite) !== 0 && insertAt + headerLength > minWriteFragment) {
        return null;
    }
    const allocation = Memory.alloc(requested + headerLength);
    const traceparent = contextRequest(allocation, false, connection);
    if (traceparent === null) {
        return null;
    }
    const header = Array.from(`traceparent: ${traceparent}\r\n`, char => char.charCodeAt(0));
    Memory.copy(allocation, buffer, insertAt);
    allocation.add(insertAt).writeByteArray(header);
    Memory.copy(allocation.add(insertAt + headerLength), buffer.add(insertAt), requested - insertAt);
    const state = {
        original: buffer,
        originalLength: requested,
        buffer: allocation,
        wireLength: requested + headerLength,
        insertAt,
        moving: (mode & sslMode.movingBuffer) !== 0,
    };
    pending.set(ssl, state);
    return state;
}

function hookIO(module, name, direction, countIndex) {
    const address = module.findExportByName(name);
    if (address === null || hooks.has(address.toString())) {
        return;
    }
    const controlAddress = module.findExportByName('SSL_ctrl');
    const getFDAddress = module.findExportByName('SSL_get_fd');
    if (controlAddress === null || getFDAddress === null) {
        return;
    }
    const control = new NativeFunction(controlAddress, 'long', ['pointer', 'int', 'long', 'pointer']);
    const getFD = new NativeFunction(getFDAddress, 'int', ['pointer']);
    const listener = Interceptor.attach(address, {
        onEnter(args) {
            const savedErrno = this.errno;
            try {
                this.key = `${this.threadId}:${direction}`;
                const nesting = depth.get(this.key) || 0;
                depth.set(this.key, nesting + 1);
                this.outer = nesting === 0;
                if (!this.outer) {
                    return;
                }
                this.connection = connectionFor(args[0], getFD);
                this.ssl = args[0].toString();
                this.buffer = args[1];
                this.requested = countIndex === null ? args[2].toInt32() : Number(args[2].toString());
                this.count = countIndex === null ? null : args[countIndex];
                this.wireRequested = this.requested;
                this.state = null;
                if (direction === 'write' && this.connection !== null) {
                    this.state = pending.get(this.ssl);
                    let text = null;
                    if (!this.state && this.requested > 0 && this.requested <= maxRequest) {
                        text = String.fromCharCode(...new Uint8Array(
                            this.buffer.readByteArray(Math.min(this.requested, maxHeaders))));
                        if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^ \r\n]/.test(text) ||
                            /^[A-Z]+ [^ \r\n]+ HTTP\/1\.[01]/.test(text)) {
                            awaitingResponse.add(this.ssl);
                        }
                    }
                    this.state = this.state || replacement(this.ssl, args[0], this.buffer, this.requested, this.connection, control, text);
                    if (this.state !== null && this.state !== undefined) {
                        const state = this.state;
                        if ((!state.moving && !this.buffer.equals(state.original)) ||
                            this.requested !== state.originalLength) {
                            send({type: 'failure', message: 'unsupported changed retry arguments', ssl: this.ssl});
                            return;
                        }
                        this.buffer = state.buffer;
                        this.wireRequested = state.wireLength;
                        args[1] = this.buffer;
                        args[2] = ptr(this.wireRequested);
                    }
                }

            } finally {
                this.errno = savedErrno;
            }
        },
        onLeave(result) {
            const savedErrno = this.errno;
            try {
                const nesting = depth.get(this.key) - 1;
                if (nesting === 0) {
                    depth.delete(this.key);
                } else {
                    depth.set(this.key, nesting);
                }
                if (!this.outer) {
                    return;
                }
                const status = result.toInt32();
                const transferred = this.count === null ? Math.max(status, 0) :
                    (status === 1 ? readSize(this.count) : 0);
                if (transferred > this.wireRequested) {
                    send({type: 'failure', message: 'transfer exceeded the supplied buffer'});
                    return;
                }
                let reported = transferred;
                let completed = null;
                if (this.state && transferred > 0) {
                    const state = this.state;
                    reported = originalOffset(state, transferred);
                    if (reported <= 0) {
                        send({type: 'failure', message: 'partial operation consumed only inserted bytes'});
                        return;
                    }
                    if (this.count === null) {
                        result.replace(reported);
                    } else {
                        writeSize(this.count, reported);
                    }
                    pending.delete(this.ssl);
                    completed = state;
                }
                try {
                    report(this.ssl, this.connection, this.buffer, transferred, direction);
                } finally {
                    if (completed) {
                        contextRequest(completed.buffer, true);
                    }
                }
                if (!enabled && pending.size === 0 && depth.size === 0) {
                    setImmediate(() => rpc.exports.stop());
                }
            } finally {
                this.errno = savedErrno;
            }
        },
    });
    hooks.set(address.toString(), listener);
    installed.push(`${module.name}:${name}`);
}

function hookModule(module) {
    const previous = new Set(hooks.keys());
    const installedCount = installed.length;
    try {
        hookIO(module, 'SSL_write', 'write', null);
        hookIO(module, 'SSL_read', 'read', null);
        hookIO(module, 'SSL_write_ex', 'write', 3);
        hookIO(module, 'SSL_read_ex', 'read', 3);
        hookIO(module, 'SSL_write_ex2', 'write', 4);
        const address = module.findExportByName('SSL_free');
        if (address !== null && !hooks.has(address.toString())) {
            hooks.set(address.toString(), Interceptor.attach(address, {
                onEnter(args) {
                    const savedErrno = this.errno;
                    try {
                        const key = args[0].toString();
                        const state = pending.get(key);
                        if (state) {
                            contextRequest(state.buffer, true);
                        }
                        pending.delete(key);
                        responsePrefixes.delete(key);
                        awaitingResponse.delete(key);
                        if (!enabled && pending.size === 0 && depth.size === 0) {
                            setImmediate(() => rpc.exports.stop());
                        }
                    } finally {
                        this.errno = savedErrno;
                    }
                },
            }));
        }
    } catch (error) {
        for (const [address, listener] of hooks) {
            if (!previous.has(address)) {
                listener.detach();
                hooks.delete(address);
            }
        }
        installed.length = installedCount;
        failures.push(String(error));
        send({type: 'failure', message: String(error), module: module.name});
    }
}

rpc.exports = {
    start() {
        if (Process.pointerSize !== 8 || !['x64', 'arm64'].includes(Process.arch)) {
            throw new Error('Frida propagation requires a 64-bit x64 or arm64 process');
        }
        ioctl = new NativeFunction(Module.getGlobalExportByName('ioctl'), 'int', ['int', 'uint', 'pointer']);
        inetPton = new NativeFunction(Module.getGlobalExportByName('inet_pton'), 'int', ['int', 'pointer', 'pointer']);
        observer = Process.attachModuleObserver({onAdded: hookModule});
        Interceptor.flush();
        if (failures.length !== 0) {
            throw new Error(failures.join('; '));
        }
        enabled = true;
        return {installed, pointerSize: Process.pointerSize, architecture: Process.arch};
    },
    snapshot() {
        return {pending: pending.size, depth: depth.size, hooks: installed};
    },
    stop() {
        enabled = false;
        if (observer !== null) {
            observer.detach();
            observer = null;
        }
        if (pending.size !== 0 || depth.size !== 0) {
            return false;
        }
        for (const listener of hooks.values()) {
            listener.detach();
        }
        hooks.clear();
        pending.clear();
        depth.clear();
        responsePrefixes.clear();
        awaitingResponse.clear();
        return true;
    },
};
