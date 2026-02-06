plugins {
    java
}

group = "io.opentelemetry.obi"
version = "0.1.0"

subprojects {
    apply(plugin = "java")

    configure<JavaPluginExtension> {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    repositories {
        mavenCentral()
    }
}

// Copy obi-java-agent JARs for each arch into root build/ (obi-java-agent-x86_64.jar, obi-java-agent-arm64.jar)
val copyObiJavaAgentJars by tasks.registering(Copy::class) {
    dependsOn(":loader:obiJavaAgentX86_64", ":loader:obiJavaAgentArm64")
    from(project(":loader").tasks.named("obiJavaAgentX86_64").get().outputs.files)
    from(project(":loader").tasks.named("obiJavaAgentArm64").get().outputs.files)
    into(layout.buildDirectory)
    rename { name ->
        when {
            name.contains("x86_64") -> "obi-java-agent-x86_64.jar"
            name.contains("arm64") -> "obi-java-agent-arm64.jar"
            else -> name
        }
    }
}

tasks.named("jar") {
    dependsOn(copyObiJavaAgentJars)
}

tasks.named("build") {
    dependsOn(copyObiJavaAgentJars)
}

tasks.named("test") {
    dependsOn(copyObiJavaAgentJars)
}