import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Firebase is optional until the production Android application is registered.
// A developer can build and use the local application without Firebase
// credentials. Adding this file activates the generated Firebase resources.
if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

val releasePropertiesFile = rootProject.file("key.properties")
val releaseProperties = Properties().apply {
    if (releasePropertiesFile.exists()) {
        releasePropertiesFile.inputStream().use(::load)
    }
}

android {
    namespace = "app.autharo.authenticator"
    compileSdk = flutter.compileSdkVersion
    // Pinned rather than inherited: the Rust core is cross-compiled against
    // this NDK, so a Flutter upgrade that moves the default would silently
    // change the toolchain the native library was built with.
    //
    // 28.2 rather than 27.2 because several plugins require it, and the NDK is
    // backward compatible. Raising this is safe; lowering it breaks the build.
    ndkVersion = "28.2.13676358"

    // PRD NFR-04 asks for per-ABI splits so the download stays under 40 MB
    // once the Rust core ships four times over. That is a build-invocation
    // concern, not a gradle one: Flutter drives abiFilters itself, and a
    // `splits { abi { ... } }` block here conflicts with it outright.
    //   Play:   flutter build appbundle          (Play splits per device)
    //   F-Droid / direct APK:
    //           flutter build apk --split-per-abi
    // A plain `flutter build apk` produces a universal APK and will exceed
    // the NFR-04 budget. See README.md.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        if (releasePropertiesFile.exists()) {
            create("release") {
                keyAlias = releaseProperties.getProperty("keyAlias")
                keyPassword = releaseProperties.getProperty("keyPassword")
                storeFile = file(releaseProperties.getProperty("storeFile"))
                storePassword = releaseProperties.getProperty("storePassword")
            }
        }
    }

    defaultConfig {
        // This is the final Android and Play listing identity. Keep it in sync
        // with Firebase and the Digital Asset Links configuration.
        applicationId = "app.autharo.authenticator"
        // PRD section 7: Android 8.0 (API 26). Passkey sign-in needs API 28 at
        // runtime, but the application still installs and runs on API 26 and
        // falls back to the password method there.
        minSdk = 26
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // Never sign a production package with the shared debug key.
            signingConfig = signingConfigs.findByName("release")
            // Remove Android and plugin code that the release application does
            // not call. Resource shrinking requires code shrinking.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        jniLibs {
            // Keep native libraries inside the installed APK. Android can map
            // them directly and does not need a second extracted copy.
            useLegacyPackaging = false
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // FR-32. The vault's wrapping key can be bound to per-use authentication,
    // and a key bound that way can only be used through a BiometricPrompt
    // carrying the Cipher as a CryptoObject. `local_auth` pulls this in
    // transitively, but the keystore code depends on it directly and a
    // transitive dependency is one a plugin upgrade can take away.
    implementation("androidx.biometric:biometric:1.1.0")

    // Android's supported passkey client. The Play Services adapter keeps the
    // same API available on supported devices before Android 14.
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
