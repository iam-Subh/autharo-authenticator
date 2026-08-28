import 'package:authenticator/src/services/vault_keystore.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('app.autharo.authenticator/keystore');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('wrap sends only a one-time handle to Kotlin', () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return <String, Object>{
            'ciphertext': Uint8List.fromList([1, 2, 3]),
            'nonce': Uint8List.fromList(List<int>.filled(12, 4)),
          };
        });

    final handle = Uint8List.fromList(List<int>.filled(32, 7));
    final wrapped = await VaultKeystore().wrapHandle(
      handle,
      requireUserAuthentication: true,
    );

    expect(received?.method, 'wrapHandle');
    final arguments = received!.arguments as Map<Object?, Object?>;
    expect(arguments['handle'], handle);
    expect(arguments.containsKey('plaintext'), isFalse);
    expect(arguments['requireUserAuthentication'], isTrue);
    expect(wrapped.ciphertext, [1, 2, 3]);
    expect(wrapped.nonce, List<int>.filled(12, 4));
  });

  test('unwrap returns only the Rust handle', () async {
    MethodCall? received;
    final handle = Uint8List.fromList(List<int>.generate(32, (index) => index));
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return handle;
        });

    final result = await VaultKeystore().unwrapToHandle(
      WrappedKey(
        ciphertext: Uint8List.fromList([8, 9]),
        nonce: Uint8List.fromList(List<int>.filled(12, 3)),
      ),
    );

    expect(received?.method, 'unwrapToHandle');
    expect(result, handle);
  });

  test('unwrap rejects a value that is not a valid handle', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          channel,
          (_) async => Uint8List.fromList(List<int>.filled(31, 0)),
        );

    expect(
      VaultKeystore().unwrapToHandle(
        WrappedKey(
          ciphertext: Uint8List.fromList([1]),
          nonce: Uint8List.fromList(List<int>.filled(12, 2)),
        ),
      ),
      throwsStateError,
    );
  });
}
