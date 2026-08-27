// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

// Sends Redis traffic from the moment it starts. The JVM runs with the attach
// mechanism disabled, so the agent injection OBI attempts against it can never
// complete and blocks for the whole attach timeout. Traffic from this process
// is only captured if the eBPF PID filter is enabled without waiting for that.
public class JavaRedisClient {
    private static final String HOST = "redis";
    private static final int PORT = 6379;
    private static final byte[] PING = "*1\r\n$4\r\nPING\r\n".getBytes();

    public static void main(String[] args) throws Exception {
        System.out.println("javaredisclient running: pid=" + ProcessHandle.current().pid());

        while (true) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(HOST, PORT), 2000);
                OutputStream out = s.getOutputStream();
                out.write(PING);
                out.flush();
                InputStream in = s.getInputStream();
                byte[] buf = new byte[64];
                int n = in.read(buf);
                System.out.println("ping=" + new String(buf, 0, Math.max(n, 0)).trim());
            } catch (Exception e) {
                System.out.println("ping failed: " + e);
            }
            Thread.sleep(500);
        }
    }
}
