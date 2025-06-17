pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    plugins {
        id("com.android.library") version "8.3.0"
        id("org.jetbrains.kotlin.android") version "1.9.22"
        id("org.jetbrains.kotlin.jvm") version "1.9.22"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "bedrock"

// The actual library
include(":bedrock-android")

// "Foreign Tests" (i.e. unit tests which are not bundled in the library)
include(":bedrock-tests")