package dev.authcore.authenticator

import android.os.Build
import java.io.File

internal data class DeviceIntegrityAssessment(
    val evaluated: Boolean,
    val indicators: List<String>,
)

/**
 * Reports local indicators of a modified Android system.
 *
 * A result with no indicators is not proof that the device is safe. Code that
 * runs with root access can hide every local indicator from this process.
 */
internal class DeviceIntegrityDetector(
    private val buildTags: String?,
    private val pathExists: (String) -> Boolean,
) {
    fun evaluate(): DeviceIntegrityAssessment {
        val indicators = mutableListOf<String>()
        if (buildTags?.contains("test-keys") == true) {
            indicators.add("test_keys")
        }
        if (ROOT_PATHS.any(pathExists)) {
            indicators.add("root_files")
        }
        return DeviceIntegrityAssessment(
            evaluated = true,
            indicators = indicators.distinct(),
        )
    }

    companion object {
        private val ROOT_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/adb/magisk",
            "/data/adb/modules",
        )

        fun forCurrentDevice() = DeviceIntegrityDetector(Build.TAGS) { path ->
            runCatching { File(path).exists() }.getOrDefault(false)
        }
    }
}
