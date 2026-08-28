import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:google_sign_in/google_sign_in.dart';

class IdentityProof {
  const IdentityProof({
    required this.token,
    required this.email,
    required this.provider,
  });

  final String token;
  final String email;
  final String provider;
}

class IdentityConfigurationException implements Exception {}

class EmailVerificationPending implements Exception {}

class IdentityEmailMismatch implements Exception {}

class IdentityAuthFailure implements Exception {
  const IdentityAuthFailure(this.code);

  final String code;

  @override
  String toString() => '[identity_$code]';
}

/// Proves email ownership without giving Firebase access to the vault key.
///
/// The email identity password and the vault password are separate values.
/// The server receives a Firebase ID token and the password-derived vault
/// authentication key. It never receives either plaintext password.
class IdentityAuthService {
  IdentityAuthService._();

  static final IdentityAuthService instance = IdentityAuthService._();

  Future<bool>? _initializing;
  bool _available = false;
  bool _googleInitialized = false;

  Future<bool> initialize() => _initializing ??= _initialize();

  Future<bool> _initialize() async {
    try {
      if (Firebase.apps.isEmpty) await Firebase.initializeApp();
      _available = true;
    } catch (_) {
      _available = false;
    }
    return _available;
  }

  Future<IdentityProof?> startEmailVerification({
    required String email,
    required String identityPassword,
    required String languageCode,
  }) async {
    try {
      return await _startEmailVerification(
        email: email,
        identityPassword: identityPassword,
        languageCode: languageCode,
      );
    } on FirebaseAuthException catch (error) {
      throw IdentityAuthFailure(error.code.replaceAll('-', '_'));
    }
  }

  Future<IdentityProof?> _startEmailVerification({
    required String email,
    required String identityPassword,
    required String languageCode,
  }) async {
    await _requireAvailable();
    final auth = FirebaseAuth.instance;
    await auth.setLanguageCode(languageCode);
    UserCredential credential;
    try {
      credential = await auth.createUserWithEmailAndPassword(
        email: email,
        password: identityPassword,
      );
    } on FirebaseAuthException catch (error) {
      if (error.code != 'email-already-in-use') rethrow;
      credential = await auth.signInWithEmailAndPassword(
        email: email,
        password: identityPassword,
      );
    }
    final user = credential.user;
    if (user == null) throw IdentityConfigurationException();
    if (user.emailVerified) return _proof(user, provider: 'password');
    await user.sendEmailVerification();
    return null;
  }

  Future<IdentityProof> finishEmailVerification() async {
    await _requireAvailable();
    final user = FirebaseAuth.instance.currentUser;
    if (user == null) throw IdentityConfigurationException();
    try {
      await user.reload();
    } on FirebaseAuthException catch (error) {
      throw IdentityAuthFailure(error.code.replaceAll('-', '_'));
    }
    final refreshed = FirebaseAuth.instance.currentUser;
    if (refreshed == null || !refreshed.emailVerified) {
      throw EmailVerificationPending();
    }
    return _proof(refreshed, provider: 'password');
  }

  Future<IdentityProof> signInWithGoogle() async {
    await _requireAvailable();
    if (!_googleInitialized) {
      await GoogleSignIn.instance.initialize();
      _googleInitialized = true;
    }
    final GoogleSignInAccount googleUser;
    try {
      googleUser = await GoogleSignIn.instance.authenticate();
    } on GoogleSignInException catch (error) {
      throw IdentityAuthFailure('google_${error.code.name}');
    }
    final googleAuth = googleUser.authentication;
    final idToken = googleAuth.idToken;
    if (idToken == null || idToken.isEmpty) {
      throw IdentityConfigurationException();
    }
    final credential = GoogleAuthProvider.credential(idToken: idToken);
    final UserCredential result;
    try {
      result = await FirebaseAuth.instance.signInWithCredential(credential);
    } on FirebaseAuthException catch (error) {
      throw IdentityAuthFailure(error.code.replaceAll('-', '_'));
    }
    final user = result.user;
    if (user == null || !user.emailVerified) {
      throw EmailVerificationPending();
    }
    return _proof(user, provider: 'google.com');
  }

  Future<IdentityProof> freshProof() async {
    await _requireAvailable();
    final user = FirebaseAuth.instance.currentUser;
    if (user == null || !user.emailVerified) {
      throw EmailVerificationPending();
    }
    final provider = user.providerData
        .map((value) => value.providerId)
        .firstWhere(
          (value) => value == 'google.com' || value == 'password',
          orElse: () => 'firebase',
        );
    return _proof(user, provider: provider);
  }

  Future<void> clear() async {
    if (!_available) return;
    await FirebaseAuth.instance.signOut();
  }

  Future<IdentityProof> _proof(User user, {required String provider}) async {
    final email = user.email;
    final token = await user.getIdToken(true);
    if (email == null || email.isEmpty || token == null || token.isEmpty) {
      throw IdentityConfigurationException();
    }
    return IdentityProof(token: token, email: email, provider: provider);
  }

  Future<void> _requireAvailable() async {
    if (!await initialize()) throw IdentityConfigurationException();
  }
}
