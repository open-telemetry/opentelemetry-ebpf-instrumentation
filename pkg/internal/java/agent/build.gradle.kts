import org.cyclonedx.model.Component

plugins {
    java
    id("com.gradleup.shadow") version "9.4.1"
    id("com.github.jk1.dependency-license-report") version "3.1.2"
    id("me.champeau.jmh") version "0.7.3"
    id("org.cyclonedx.bom") version "3.2.4"
    id("com.diffplug.spotless")
}

group = "io.opentelemetry.obi"
version = "0.1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        // Use Google Java Format
        googleJavaFormat()
        // Or use Eclipse formatter
        // eclipse()

        // Remove unused imports
        removeUnusedImports()

        // Trim trailing whitespace
        trimTrailingWhitespace()

        // End files with newline
        endWithNewline()

        // Target files
        target("src/**/*.java")
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.bytebuddy:byte-buddy:1.18.8-jdk5")
    implementation("net.bytebuddy:byte-buddy-agent:1.18.8-jdk5")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.3")
    testImplementation("org.junit.platform:junit-platform-launcher:1.14.3")
    testImplementation("org.awaitility:awaitility:4.3.0")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.3")
}

tasks.register("prepareKotlinBuildScriptModel"){}

tasks.test {
    useJUnitPlatform()
}

// Automatic JNI header generation during compilation
// Outputs to the build directory to avoid affecting the source tree
tasks.compileJava {
    options.headerOutputDirectory.set(layout.buildDirectory.dir("generated/jni-headers"))
}

// Ensure spotless runs after compileJava to avoid task ordering issues
tasks.named("spotlessJava") {
    mustRunAfter(tasks.compileJava)
}

val currentArch = if (System.getProperty("os.arch").contains("aarch64")) "aarch64" else "amd64"

// Build the native JNI library
tasks.register<Exec>("buildNativeLib-amd64") {
    group = "build"
    description = "Build the JNI native library (libobijni.so)"

    dependsOn("compileJava")

    workingDir = projectDir
    val cc = if (currentArch == "amd64") "gcc" else "gcc-x86-64-linux-gnu"
    commandLine("make", "-f", "Makefile.jni", "CC=$cc", "BUILD_DIR=build/jni/linux-amd64", "TARGET_DIR=target/classes/native/linux-amd64")

    doLast {
        println("OBI JNI library built successfully")
    }
}

tasks.register<Exec>("buildNativeLib-aarch64") {
    group = "build"
    description = "Build the JNI native library (libobijni.so)"

    dependsOn("compileJava")

    workingDir = projectDir
    val cc = if (currentArch == "aarch64") "gcc" else "aarch64-linux-gnu-gcc"
    commandLine("make", "-f", "Makefile.jni", "CC=$cc", "BUILD_DIR=build/jni/linux-aarch64", "TARGET_DIR=target/classes/native/linux-aarch64")

    doLast {
        println("OBI JNI library built successfully")
    }
}

// Clean native library
tasks.register<Delete>("cleanNativeLib") {
    group = "build"
    description = "Clean the JNI native library build artifacts"
    
    delete(file("build"))
    delete(file("target/classes/native/linux-amd64/libobijni.so"))
    delete(file("target/classes/native/linux-aarch64/libobijni.so"))
}

val jmhIncludes: String? by project
val jmhProfilers: String? by project

jmh {
    includes.set(listOf(".*Benchmark.*"))
    jmhIncludes?.let {
        includes.set(listOf(it))
    }
    jmhProfilers?.let { profilersStr ->
        profilers.set(profilersStr.split(",").map { p: String -> p.trim() })
    }
    benchmarkMode.set(listOf("avgt"))
    timeUnit.set("ns")
    warmupIterations.set(3)
    iterations.set(5)
    fork.set(1)
    jvmArgs.set(listOf("-Xmx2G"))
}

val nativeOnly: String? by project
val nativeArches: List<String> = if (nativeOnly != null) {
    val osArch = System.getProperty("os.arch")
    listOf(if (osArch.contains("aarch64")) "aarch64" else "amd64")
} else {
    listOf("amd64", "aarch64")
}

tasks.shadowJar {
    nativeArches.forEach { arch -> dependsOn("buildNativeLib-$arch") }

    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")

    // Include the native libraries in the JAR
    from(file("target/classes")) {
        nativeArches.forEach { arch -> include("native/linux-$arch/libobijni.so") }
    }

    manifest {
        attributes(
            "Premain-Class" to "io.opentelemetry.obi.java.Agent",
            "Agent-Class" to "io.opentelemetry.obi.java.Agent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Main-Class" to "io.opentelemetry.obi.java.Agent"
        )
    }
    relocate("net.bytebuddy", "io.opentelemetry.obi.net.bytebuddy")
    // Exclude META-INF files as in Maven Shade plugin
    exclude("META-INF/**")
    exclude("META-INF/versions/9/module-info.class")
}

licenseReport {
    outputDir = layout.buildDirectory.dir("reports/dependency-license").get().asFile.absolutePath
    configurations = arrayOf("runtimeClasspath")
    renderers = arrayOf<com.github.jk1.license.render.ReportRenderer>(
        com.github.jk1.license.render.TextReportRenderer("THIRD_PARTY_LICENSES.txt"),
        com.github.jk1.license.render.CsvReportRenderer("THIRD_PARTY_LICENSES.csv"),
    )
}

tasks.cyclonedxDirectBom {
    includeConfigs = listOf("runtimeClasspath")
    skipConfigs = listOf("testCompileClasspath", "testRuntimeClasspath")
    projectType.set(Component.Type.APPLICATION)
    componentName.set("obi-java-agent")
    componentVersion.set(providers.environmentVariable("OBI_JAVA_AGENT_SBOM_VERSION").orElse(version.toString()))
    includeBuildSystem.set(true)
}
