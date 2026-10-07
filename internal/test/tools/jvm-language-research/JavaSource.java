// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

public class JavaSource {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("java source entry");
        Thread.sleep(Long.getLong("obi.research.wait", 0L));
    }
}
