# Rust resolves these names through JNI. Keep them if release shrinking is
# enabled later.
-keep class dev.authcore.authenticator.NativeSessionBridge { *; }
-keep class dev.authcore.authenticator.NativeVaultBridge { *; }
-keep class dev.authcore.authenticator.SyncTokenStore { *; }
