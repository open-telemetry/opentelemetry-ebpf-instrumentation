plugins {
    java
    id("com.gradleup.shadow") version "8.3.9"
    id("me.champeau.jmh") version "0.7.3"
    id("com.diffplug.spotless") version "8.2.0"
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
    implementation("net.bytebuddy:byte-buddy:1.18.4")
    implementation("net.bytebuddy:byte-buddy-agent:1.17.8")
    implementation("com.github.ben-manes.caffeine:caffeine:2.9.3")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.3")
    testImplementation("org.junit.platform:junit-platform-launcher:1.10.2")
    testImplementation("org.awaitility:awaitility:4.3.0")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.3")
}

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

val isMac = System.getProperty("os.name").lowercase().contains("mac")
val agentDir = projectDir.absolutePath
val dockerImage = "eclipse-temurin:21-jdk"

fun execDocker(arch: String, platform: String) =
    listOf(
        "docker", "run", "--rm",
        "--platform", platform,
        "-v", "$agentDir:/work", "-w", "/work",
        dockerImage,
        "bash", "-c",
        "apt-get update -qq && apt-get install -y -qq make clang && make -f Makefile.jni native ARCH=$arch"
    )

// Build Linux libobijni.so for x86_64 (always via Docker so it works on macOS and Linux)
tasks.register<Exec>("buildNativeLibAmd64") {
    group = "build"
    description = "Build Linux libobijni.so for x86_64 (amd64)"
    dependsOn("compileJava")
    workingDir = projectDir
    commandLine(execDocker("amd64", "linux/amd64"))
    doLast { println("OBI JNI library (amd64) built: target/classes/linux-amd64/libobijni.so") }
}

// Build Linux libobijni.so for arm64 (always via Docker)
tasks.register<Exec>("buildNativeLibArm64") {
    group = "build"
    description = "Build Linux libobijni.so for arm64"
    dependsOn("compileJava")
    workingDir = projectDir
    commandLine(execDocker("arm64", "linux/arm64"))
    doLast { println("OBI JNI library (arm64) built: target/classes/linux-arm64/libobijni.so") }
}

// Build both architectures (for convenience)
tasks.register("buildNativeLibAll") {
    group = "build"
    description = "Build Linux libobijni.so for both x86_64 and arm64"
    dependsOn("buildNativeLibAmd64", "buildNativeLibArm64")
}

// Clean native libraries
tasks.register<Delete>("cleanNativeLib") {
    group = "build"
    description = "Clean the JNI native library build artifacts"
    delete(file("build/linux-amd64"), file("build/linux-arm64"))
    delete(file("target/classes/linux-amd64"), file("target/classes/linux-arm64"))
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

val shadowJarManifest = mapOf(
    "Premain-Class" to "io.opentelemetry.obi.java.Agent",
    "Agent-Class" to "io.opentelemetry.obi.java.Agent",
    "Can-Redefine-Classes" to "true",
    "Can-Retransform-Classes" to "true",
    "Main-Class" to "io.opentelemetry.obi.java.Agent"
)

// Agent JAR for x86_64 (default shadowJar)
tasks.shadowJar {
    dependsOn("buildNativeLibAmd64")
    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("linux-x86_64")
    from(file("target/classes/linux-amd64")) {
        include("libobijni.so")
    }
    manifest { attributes(shadowJarManifest) }
    relocate("com.github", "io.opentelemetry.obi.com.github")
    relocate("net.bytebuddy", "io.opentelemetry.obi.net.bytebuddy")
    exclude("META-INF/**")
    exclude("META-INF/versions/9/module-info.class")
}

// Agent JAR for arm64
tasks.register<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJarArm64") {
    group = "build"
    description = "Build agent JAR for Linux arm64"
    dependsOn("buildNativeLibArm64")
    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("linux-arm64")
    from(sourceSets.main.get().output)
    from(file("target/classes/linux-arm64")) {
        include("libobijni.so")
    }
    configurations = listOf(project.configurations.runtimeClasspath.get())
    manifest { attributes(shadowJarManifest) }
    relocate("com.github", "io.opentelemetry.obi.com.github")
    relocate("net.bytebuddy", "io.opentelemetry.obi.net.bytebuddy")
    exclude("META-INF/**")
    exclude("META-INF/versions/9/module-info.class")
}