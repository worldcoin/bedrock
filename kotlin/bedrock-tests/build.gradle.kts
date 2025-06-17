// This build.gradle uses a JVM-only testing engine for unit testing.
// Note this is separate from the build.gradle used for building and publishing the actual library.

plugins {
    kotlin("jvm") version "1.9.23"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.13.0")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("junit:junit:4.13.2")
}

sourceSets {
    test {
        kotlin.srcDirs(
            "$rootDir/bedrock-android/src/main/java/uniffi/bedrock"
        )
    }
}

tasks.test {
    useJUnit()
    systemProperty("jna.library.path", "${rootDir}/libs")
    reports.html.required.set(false)
}