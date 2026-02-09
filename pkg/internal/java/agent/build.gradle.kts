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

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.3")
    testImplementation("org.junit.platform:junit-platform-launcher:1.10.2")
    testImplementation("org.awaitility:awaitility:4.3.0")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.3")
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

// Build the native JNI library
tasks.register<Exec>("buildNativeLib") {
    group = "build"
    description = "Build the JNI native library (libobijni.so)"
    
    dependsOn("compileJava")
    
    workingDir = projectDir
    commandLine("make", "-f", "Makefile.jni")
    
    doLast {
        println("OBI JNI library built successfully")
    }
}

// Clean native library
tasks.register<Delete>("cleanNativeLib") {
    group = "build"
    description = "Clean the JNI native library build artifacts"
    
    delete(file("build"))
    delete(file("target/classes/libobijni.so"))
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

tasks.shadowJar {
    dependsOn("buildNativeLib")
    
    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")
    
    // Include the native library in the JAR
    from(file("target/classes")) {
        include("libobijni.so")
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