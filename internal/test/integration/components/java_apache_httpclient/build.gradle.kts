plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.apache.httpcomponents:httpclient:4.5.14")
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
