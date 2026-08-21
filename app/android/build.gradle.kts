allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
// flutter_secure_storage 11.0.0 hardcodes `compileSdk = 37`, but the Android
// SDK publishes no bare `android-37` platform — only `android-37.0` and
// `android-37.1` — so that request cannot resolve and the build fails with
// "Failed to find target with hash string 'android-37'".
//
// Flutter's own default is 36, which is what every other plugin here compiles
// against, so the fix is to hold the whole tree at 36 rather than chase a
// platform that does not exist. Revisit when the plugin stops pinning 37.
subprojects {
    afterEvaluate {
        val android = extensions.findByName("android") ?: return@afterEvaluate
        runCatching {
            val setter = android.javaClass.methods.first {
                it.name == "setCompileSdkVersion" &&
                    it.parameterTypes.size == 1 &&
                    it.parameterTypes[0] == Int::class.javaPrimitiveType
            }
            setter.invoke(android, 36)
        }
    }
}

subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
