package dev.authcore.authenticator;

/** Transfers vault secrets between Rust and Kotlin without using Dart. */
public final class NativeVaultBridge {
    static {
        System.loadLibrary("rust_lib_authenticator");
    }

    private NativeVaultBridge() {}

    /** Stores a Kotlin-owned secret in Rust and returns a one-time handle. */
    public static native byte[] storeSecret(byte[] secret);

    /** Consumes a Rust-owned handle and returns the secret to Kotlin. */
    public static native byte[] takeSecret(byte[] handle);

    /** Removes a setup handle that Kotlin did not consume. */
    public static native void discardSecret(byte[] handle);

    /** Clears all pending handles and device-slot operations. */
    public static native void cancelPendingOperation();
}
