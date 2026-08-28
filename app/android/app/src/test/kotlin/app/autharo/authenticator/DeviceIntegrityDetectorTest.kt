package app.autharo.authenticator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceIntegrityDetectorTest {
    @Test
    fun `test signing keys are reported separately`() {
        val result = DeviceIntegrityDetector("release-keys test-keys") { false }.evaluate()
        assertTrue(result.evaluated)
        assertEquals(listOf("test_keys"), result.indicators)
    }

    @Test
    fun `known root paths are reported separately`() {
        val result = DeviceIntegrityDetector("release-keys") { path ->
            path == "/data/adb/magisk"
        }.evaluate()
        assertEquals(listOf("root_files"), result.indicators)
    }

    @Test
    fun `no indicator is not represented as a safe verdict`() {
        val result = DeviceIntegrityDetector("release-keys") { false }.evaluate()
        assertTrue(result.evaluated)
        assertTrue(result.indicators.isEmpty())
    }
}
