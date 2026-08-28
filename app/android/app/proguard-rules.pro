# Rust resolves these names through JNI. Keep them if release shrinking is
# enabled later.
-keep class app.autharo.authenticator.NativeSessionBridge { *; }
-keep class app.autharo.authenticator.NativeVaultBridge { *; }
-keep class app.autharo.authenticator.SyncTokenStore { *; }
