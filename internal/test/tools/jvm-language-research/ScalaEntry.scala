// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

object ScalaEntry {
  def main(args: Array[String]): Unit = {
    println("scala entry")
    JavaHelper.waitForInspection()
  }
}
