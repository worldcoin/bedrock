import java.io.ByteArrayOutputStream

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "com.toolsforhumanity.bedrock"
    compileSdk = 33

    defaultConfig {
        minSdk = 23
        @Suppress("deprecation")
        targetSdk = 33
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {
                groupId = "com.toolsforhumanity"
                artifactId = "bedrock"

                version = if (project.hasProperty("versionName")) {
                    project.property("versionName") as String
                } else {
                    val stdout = ByteArrayOutputStream()
                    exec {
                        commandLine = listOf(
                            "curl", "-s", "-H",
                            "Authorization: token ${System.getenv("GITHUB_TOKEN")}",
                            "https://api.github.com/repos/worldcoin/bedrock/releases/latest"
                        )
                        standardOutput = stdout
                    }
                    val response = stdout.toString()
                    val tag = Regex("\"tag_name\":\\s*\"(.*?)\"")
                        .find(response)?.groupValues?.get(1) ?: "0.0.0"
                    "$tag"
                }

                afterEvaluate {
                    from(components["release"])
                }
            }
        }

        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/worldcoin/bedrock")
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

dependencies {
    // UniFFI requires JNA for native calls
    implementation("net.java.dev.jna:jna:5.13.0")
    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.appcompat:appcompat:1.4.1")
    implementation("com.google.android.material:material:1.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}