plugins {
    java
}

repositories {
    mavenCentral()
}

val apacheHttpClientVersion = providers.gradleProperty("apacheHttpClientVersion").getOrElse("4.5.14")

dependencies {
    implementation("org.apache.httpcomponents:httpclient:$apacheHttpClientVersion")
}

sourceSets.main {
    java.setSrcDirs(listOf("."))
    java.setIncludes(listOf("Main.java"))
}

tasks.compileJava {
    options.release.set(8)
}

tasks.register<Copy>("runtimeLibraries") {
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("libs"))
}
