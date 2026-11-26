// Default Flutter widget test – kept so `flutter test` has something to run
// in CI and does not exit with "no tests ran" (Phase 0 requirement).
//
// Extended per-feature tests are added in Phase 2 onwards under test/features/.

import 'package:flutter_test/flutter_test.dart';
import 'package:sokolink/main.dart';

void main() {
  testWidgets('SokoLink placeholder screen renders app title',
      (WidgetTester tester) async {
    await tester.pumpWidget(const SokoLinkApp());
    expect(find.text('SokoLink'), findsOneWidget);
  });
}
