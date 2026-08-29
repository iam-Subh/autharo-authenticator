import 'dart:io';

import 'package:qr/qr.dart';

const _uri =
    'otpauth://totp/Autharo%20Demo:demo%40autharo.app?secret='
    'JBSWY3DPEHPK3PXPGEZDGNBVGY3TQOJQ&issuer=Autharo%20Demo&algorithm=SHA1&digits=6&period=30';

void main() {
  final code = QrCode.fromData(
    data: _uri,
    errorCorrectLevel: QrErrorCorrectLevel.M,
  );
  final image = QrImage(code);
  const quietZone = 4;
  final viewBoxSize = image.moduleCount + (quietZone * 2);
  final path = StringBuffer();

  for (var row = 0; row < image.moduleCount; row++) {
    for (var column = 0; column < image.moduleCount; column++) {
      if (image.isDark(row, column)) {
        path.write('M${column + quietZone} ${row + quietZone}h1v1h-1z');
      }
    }
  }

  final svg =
      '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $viewBoxSize $viewBoxSize" shape-rendering="crispEdges" role="img" aria-label="Autharo Demo setup QR code">
  <rect width="100%" height="100%" fill="#fff"/>
  <path d="$path" fill="#0b0c10"/>
</svg>
''';

  File('../hosting/autharo-demo-qr.svg').writeAsStringSync(svg);
}
