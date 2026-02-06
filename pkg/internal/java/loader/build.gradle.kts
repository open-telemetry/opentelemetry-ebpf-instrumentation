import com.diffplug.gradle.spotless.SpotlessExtension

plugins {
    java
    id("com.gradleup.shadow") version "8.3.9"
    id("com.diffplug.spotless") version "8.2.0"
}

// We need this dependency to load the resource JNA shared libraries
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
}

configure<SpotlessExtension> {
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

// Copy agent JAR into loader resources (used for default processResources / single-arch build)
val copyAgentShadowJar by tasks.registering(Copy::class) {
    dependsOn(":agent:shadowJar")
    from(project(":agent").tasks.named("shadowJar").get().outputs.files)
    into("$projectDir/src/main/resources/agent")
    rename { "agent.zip" }
}

// Per-architecture agent copy (for obi-java-agent-<arch>.jar)
val copyAgentX86_64 by tasks.registering(Copy::class) {
    dependsOn(":agent:shadowJar")
    from(project(":agent").tasks.named("shadowJar").get().outputs.files)
    into(layout.buildDirectory.dir("loader-resources-x86_64/agent"))
    rename { "agent.zip" }
}
val copyAgentArm64 by tasks.registering(Copy::class) {
    dependsOn(":agent:shadowJarArm64")
    from(project(":agent").tasks.named("shadowJarArm64").get().outputs.files)
    into(layout.buildDirectory.dir("loader-resources-arm64/agent"))
    rename { "agent.zip" }
}

tasks.named("spotlessJava") {
    mustRunAfter(copyAgentShadowJar)
}

tasks.clean {
    doFirst {
        delete(fileTree("$projectDir/src/main/resources/agent"))
        delete(layout.buildDirectory.dir("loader-resources-x86_64"))
        delete(layout.buildDirectory.dir("loader-resources-arm64"))
    }
}

tasks.processResources {
    dependsOn(copyAgentShadowJar)
}

val loaderManifest = mapOf(
    "Main-Class" to "io.opentelemetry.obi.java.Loader",
    "Premain-Class" to "io.opentelemetry.obi.java.Loader",
    "Agent-Class" to "io.opentelemetry.obi.java.Loader",
    "Can-Redefine-Classes" to "true",
    "Can-Retransform-Classes" to "true"
)

// Default loader JAR (x86_64 agent; backward compat)
tasks.shadowJar {
    archiveBaseName.set("loader")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")
    manifest { attributes(loaderManifest) }
}

// obi-java-agent-x86_64.jar (loader + x86_64 agent)
tasks.register<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("obiJavaAgentX86_64") {
    group = "build"
    description = "Build obi-java-agent JAR for Linux x86_64"
    dependsOn(copyAgentX86_64, tasks.compileJava)
    archiveBaseName.set("obi-java-agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("x86_64")
    from(tasks.compileJava.get().outputs.files)
    from(layout.buildDirectory.dir("loader-resources-x86_64"))
    configurations = listOf(project.configurations.runtimeClasspath.get())
    manifest { attributes(loaderManifest) }
}

// obi-java-agent-arm64.jar (loader + arm64 agent)
tasks.register<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("obiJavaAgentArm64") {
    group = "build"
    description = "Build obi-java-agent JAR for Linux arm64"
    dependsOn(copyAgentArm64, tasks.compileJava)
    archiveBaseName.set("obi-java-agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("arm64")
    from(tasks.compileJava.get().outputs.files)
    from(layout.buildDirectory.dir("loader-resources-arm64"))
    configurations = listOf(project.configurations.runtimeClasspath.get())
    manifest { attributes(loaderManifest) }
}
