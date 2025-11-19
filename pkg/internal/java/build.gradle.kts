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

val copyLoaderJar by tasks.registering(Copy::class) {
    dependsOn(":loader:shadowJar")
    from("$projectDir/loader/build/libs/loader-$version-shaded.jar")
    into("$projectDir/build")
    rename { "obi-java-agent.jar" }
}

tasks.named("jar") {
    dependsOn(copyLoaderJar)
}

// Ensure root test task depends on copyLoaderJar
tasks.named("test") {
    dependsOn(copyLoaderJar)
}