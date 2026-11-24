/// SokoLink – entry point.
///
/// Security notes:
/// - API base URL comes from --dart-define at build time, never hardcoded.
/// - No secrets or API keys are stored in the app (Security rule 10).
/// - Tokens are stored in [FlutterSecureStorage], not SharedPreferences (T15).
/// - Debug logs are stripped in release builds (Security rule 13).
library;

import 'package:flutter/material.dart';

/// API base URL supplied at build time:
///   flutter run --dart-define=API_BASE_URL=https://api.sokolink.rw
/// Defaults to localhost for development.
const String apiBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://10.0.2.2:8000', // Android emulator loopback
);

void main() {
  runApp(const SokoLinkApp());
}

class SokoLinkApp extends StatelessWidget {
  const SokoLinkApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SokoLink',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1565C0)),
        useMaterial3: true,
      ),
      home: const _PlaceholderScreen(),
    );
  }
}

/// Temporary placeholder – replaced in Phase 2 with the sign-in screen.
class _PlaceholderScreen extends StatelessWidget {
  const _PlaceholderScreen();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              'SokoLink',
              style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(
              'Phase 0 – foundation only',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ],
        ),
      ),
    );
  }
}
