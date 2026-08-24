plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "dev.authcore.authenticator"
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

    defaultConfig {
        // NOTE: this identity is provisional. It is the Play listing identity
        // and it must appear in assetlinks.json for the S7 passkey work, so
        // settle it before either of those.
        applicationId = "dev.authcore.authenticator"
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
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
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
