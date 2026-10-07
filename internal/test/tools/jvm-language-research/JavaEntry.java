// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

public class JavaEntry {
    public static void main(String[] args) {
        System.out.println(KotlinHelper.message());
		JavaHelper.waitForInspection();
    }
}
