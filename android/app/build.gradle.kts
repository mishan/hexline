plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ktlint)
}

val repoRoot = rootDir.parentFile

// The Rust core for every ABI the app ships, and its Kotlin bindings, made
// by scripts/build-core.sh so a shell and Gradle build the same thing.
val buildCore by tasks.registering(Exec::class) {
    workingDir = repoRoot
    commandLine(
        "scripts/build-core.sh",
        layout.buildDirectory
            .dir("rust")
            .get()
            .asFile.path,
    )
    inputs.dir(repoRoot.resolve("crates"))
    inputs.files(repoRoot.resolve("Cargo.toml"), repoRoot.resolve("Cargo.lock"))
    outputs.dir(layout.buildDirectory.dir("rust"))
}

// The verifier's Kotlin half must be the version its crate was built
// against, which is whatever Cargo.lock resolved.
val rustlsVerifierVersion: String =
    providers.fileContents(rootProject.layout.projectDirectory.file("../Cargo.lock")).asText.get().lines().let { lines ->
        val at = lines.indexOfFirst { it == "name = \"rustls-platform-verifier-android\"" }
        require(at >= 0) { "rustls-platform-verifier-android is not in Cargo.lock" }
        lines[at + 1].substringAfter('"').substringBefore('"')
    }

android {
    namespace = "org.foggyden.hexline"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "org.foggyden.hexline"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    // F-Droid's build carries nothing proprietary; Play's will add FCM.
    flavorDimensions += "distribution"
    productFlavors {
        create("fdroid") { dimension = "distribution" }
        create("play") { dimension = "distribution" }
    }

    buildFeatures { compose = true }

    // Static paths, made before any variant compiles by `preBuild`'s
    // dependency on buildCore.
    sourceSets["main"].kotlin.srcDir(
        layout.buildDirectory
            .dir("rust/kotlin")
            .get()
            .asFile,
    )
    sourceSets["main"].jniLibs.srcDir(
        layout.buildDirectory
            .dir("rust/jniLibs")
            .get()
            .asFile,
    )

    lint {
        warningsAsErrors = true
        abortOnError = true
        // A library's own checks built for another lint; not ours to fix.
        disable += "ObsoleteLintCustomCheck"
    }

    testOptions {
        // The JVM tests call the core through the same bindings, loaded
        // from a build for the host.
        // The bindings ask Build.VERSION which cleaner to use; on the JVM
        // the stub answers 0 and they take JNA's.
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            it.dependsOn(buildCore)
            it.systemProperty(
                "jna.library.path",
                layout.buildDirectory
                    .dir("rust/host")
                    .get()
                    .asFile.path,
            )
        }
    }
}

kotlin {
    jvmToolchain(21)
    compilerOptions { allWarningsAsErrors = true }
}

tasks.named("preBuild") { dependsOn(buildCore) }

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)
    implementation("${libs.jna.get()}@aar")
    implementation(libs.coroutines)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.process)
    implementation(libs.rustls.platform.verifier) { version { strictly(rustlsVerifierVersion) } }

    testImplementation(libs.junit)
    testImplementation(libs.jna)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.ext)
    androidTestImplementation(libs.androidx.test.runner)
    debugImplementation(libs.compose.ui.test.manifest)
}

// The bindings are uniffi's, not ours to format.
ktlint {
    filter { exclude { it.file.path.contains("/build/rust/") } }
}
tasks.matching { it.name.startsWith("runKtlint") }.configureEach { mustRunAfter(buildCore) }
