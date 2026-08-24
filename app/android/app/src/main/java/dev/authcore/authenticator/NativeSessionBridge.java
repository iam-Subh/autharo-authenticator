package dev.authcore.authenticator;

/** Installs the Kotlin token store directly into the Rust library. */
public final class NativeSessionBridge {
    static {
        System.loadLibrary("rust_lib_authenticator");
    }

    private NativeSessionBridge() {}

    /**
     * Rust keeps a global reference to {@code store}. The store holds only the
     * application context, so it remains valid across Activity recreation.
     */
    public static native void installTokenStore(SyncTokenStore store);
}
