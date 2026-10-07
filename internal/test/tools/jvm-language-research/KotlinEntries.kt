// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

object KotlinHelper {
    @JvmStatic
    fun message(): String = "kotlin helper"
}

fun main() {
    println(JavaHelper.message())
    JavaHelper.waitForInspection()
}

object ObjectEntry {
    @JvmStatic
    fun main(args: Array<String>) {
        println(JavaHelper.message())
        JavaHelper.waitForInspection()
    }
}

class CompanionEntry {
    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            println(JavaHelper.message())
            JavaHelper.waitForInspection()
        }
    }
}
