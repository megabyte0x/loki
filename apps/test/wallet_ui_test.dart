import 'dart:async';
import 'dart:convert';
import 'dart:ui' show SemanticsAction;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:loki_signer/main.dart';
import 'package:loki_signer/wallet_api.dart';
import 'package:material_ui/material_ui.dart';

import 'fixture_wallet.dart';

const _walletChannel = MethodChannel('cash.loki/wallet');

TestDefaultBinaryMessenger get _messenger =>
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

void _mockMac(FixtureWallet wallet, Map<String, Function> methods) {
  _messenger.setMockMethodCallHandler(_walletChannel, (call) async {
    if (call.method == 'request') {
      final path = call.arguments['path'] as String;
      final body = (call.arguments['body'] as Map?)?.cast<String, dynamic>();
      final result = await wallet.request(path, body);
      if (methods[path] case final handler?) await handler();
      return result;
    }
    expect(call.arguments, isNull, reason: call.method);
    if (methods[call.method] case final handler?) return await handler();
    if (call.method == 'profile') return wallet.profile();
    throw MissingPluginException(call.method);
  });
  addTearDown(() => _messenger.setMockMethodCallHandler(_walletChannel, null));
}

Future<void> _nativePromptChanged(bool active) async {
  await _messenger.handlePlatformMessage(
    _walletChannel.name,
    const StandardMethodCodec().encodeMethodCall(
      MethodCall('nativePromptChanged', active),
    ),
    null,
  );
}

void main() {
  Future<void> start(
    WidgetTester tester,
    WalletApi api, {
    ThemeMode theme = ThemeMode.light,
  }) async {
    await tester.binding.setSurfaceSize(const Size(1040, 644));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(LokiApp(api: api, initialTheme: theme));
    await tester.pump();
  }

  Future<void> tap(WidgetTester tester, Finder finder) async {
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 350));
  }

  void expectInline(WidgetTester tester) {
    expect(
      tester.state<NavigatorState>(find.byType(Navigator)).canPop(),
      isFalse,
    );
  }

  testWidgets(
    'History keeps its rows and only exposes the confirmed transaction externally',
    (tester) async {
      final api = FixtureWallet()..confirmed = false;
      String? copied;
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = call.arguments['text'] as String;
        }
        return null;
      });
      addTearDown(
        () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
      );
      await start(tester, api);
      await tap(tester, find.text('History').first);
      await tap(tester, find.text('Awaiting confirmation'));
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
      expect(find.byTooltip('Copy transaction id'), findsNothing);
      expect(find.text('View on ZecBlock'), findsNothing);

      api.confirmed = true;
      await tester.pump(const Duration(seconds: 3));
      await tester.pump();
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('View on ZecBlock'), findsOneWidget);
      await tester.ensureVisible(find.byTooltip('Copy transaction id'));
      await tester.pump();
      await tap(tester, find.byTooltip('Copy transaction id'));
      expect(copied, FixtureWallet.txid);
      expect(api.openedTx, isNull);
      await tester.ensureVisible(find.text('View on ZecBlock'));
      await tester.pump();
      await tap(tester, find.text('View on ZecBlock'));
      expect(api.openedTx, FixtureWallet.txid);
      await tester.ensureVisible(find.byTooltip('Close details'));
      await tester.pump();
      await tap(tester, find.byTooltip('Close details'));
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('TRANSACTION DETAILS'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('Draft keeps exact zats and requires a separate publish', (
    tester,
  ) async {
    final api = FixtureWallet();
    await start(tester, api);
    await tap(tester, find.text('Studio vault').first);
    await tap(tester, find.text('Send').last);
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), FixtureWallet.recipient);
    await tester.enterText(fields.at(1), '1.000000019');
    await tap(tester, find.text('Prepare draft'));
    expect(api.writes.where((e) => e.$1 == 'payment-draft'), isEmpty);

    await tester.enterText(fields.at(1), '0.00765431');
    await tap(tester, find.text('Prepare draft'));
    expect(
      api.writes.singleWhere((e) => e.$1 == 'payment-draft').$2['amount_zat'],
      '765431',
    );
    expect(api.writes.where((e) => e.$1 == 'payment-publish'), isEmpty);
    await tap(tester, find.text('Request approvals'));
    expect(
      api.writes.singleWhere((e) => e.$1 == 'payment-publish').$2['attempt'],
      'd' * 64,
    );
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'Proposal preview hands an exact reviewed intent to the signer only on Continue',
    (tester) async {
      final api = FixtureWallet();
      await start(tester, api);
      await tap(tester, find.text('Studio vault').first);
      await tap(tester, find.text('Review'));
      expect(find.text('Review proposal'), findsOneWidget);
      expect(find.text(FixtureWallet.recipient), findsOneWidget);
      expect(find.text('0.40000000 TAZ'), findsOneWidget);
      expect(find.text('0.00010000 TAZ'), findsOneWidget);
      expect(find.text('0.59990000 TAZ'), findsOneWidget);
      expect(find.text('Not yet signed'), findsOneWidget);
      expect(find.text('Paired coordinator'), findsOneWidget);
      expectInline(tester);
      expect(api.writes.where((e) => e.$1 == 'payment-approve'), isEmpty);
      await tap(tester, find.text('Back'));
      expect(find.text('Review proposal'), findsNothing);
      expect(api.writes.where((e) => e.$1 == 'payment-approve'), isEmpty);
      await tap(tester, find.text('Review'));
      final continueButton = find.text('Continue to signer');
      expect(
        continueButton.hitTestable(),
        findsOneWidget,
        reason: 'Button location: ${tester.getRect(continueButton)}',
      );
      await tap(tester, find.text('Continue to signer'));
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-approve').$2, {
        'vault': FixtureWallet.studio,
        'attempt': FixtureWallet.proposal,
        'review_token': 'f' * 64,
        'intent_hash': 'c' * 64,
      });
      expect(find.text('Approval requested'), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('Create and join stay in the workspace and require submission', (
    tester,
  ) async {
    final api = FixtureWallet()..inviting = true;
    String? copied;
    _messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = call.arguments['text'] as String;
      }
      return null;
    });
    addTearDown(
      () => _messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );
    await start(tester, api);
    await tap(tester, find.text('Create vault'));
    expect(find.text('VAULT DETAILS'), findsOneWidget);
    expectInline(tester);
    expect(find.text(api.coordinator), findsOneWidget);
    await tap(tester, find.widgetWithText(TextButton, 'Create vault'));
    expect(find.text('Enter a vault name of 1–80 bytes.'), findsOneWidget);
    expect(api.writes, isEmpty);
    await tester.enterText(find.byType(TextField), '  Test vault  ');
    await tap(tester, find.byTooltip('More members'));
    await tap(tester, find.byTooltip('More approvals'));
    expect(find.text('3 of 4 approvals'), findsOneWidget);
    await tap(tester, find.widgetWithText(TextButton, 'Create vault'));
    expect(api.writes.singleWhere((e) => e.$1 == 'create').$2, {
      'name': 'Test vault',
      'members': 4,
      'threshold': 3,
    });
    expect(find.text('Set up vault'), findsOneWidget);
    await tap(tester, find.text('Copy invite'));
    expect(copied, '${api.coordinator}/#invite=test-invite');
    expect(find.text('Invite copied'), findsOneWidget);
    expect(find.byType(SnackBar), findsNothing);

    await tap(tester, find.text('All vaults').first);
    await tap(tester, find.text('Join vault'));
    expect(find.text('Review vault invite'), findsOneWidget);
    expectInline(tester);
    await tester.enterText(find.byType(TextField), 'not-an-invitation');
    await tap(tester, find.text('Join vault'));
    expect(
      find.textContaining('This invite could not be read'),
      findsOneWidget,
    );
    expect(api.writes.where((e) => e.$1 == 'join'), isEmpty);
    final code = base64Url
        .encode(
          utf8.encode(
            jsonEncode({
              'vault': FixtureWallet.reserve,
              'token': base64Url
                  .encode(List<int>.filled(32, 1))
                  .replaceAll('=', ''),
              'name': 'Ops vault',
              'creator_base_url': api.coordinator,
              'slot': 3,
              'members': 4,
              'threshold': 2,
            }),
          ),
        )
        .replaceAll('=', '');
    await tester.enterText(find.byType(TextField), code);
    await tester.pump();
    expect(find.text('Ops vault'), findsOneWidget);
    await tester.enterText(
      find.byType(TextField),
      'https://example.test/?invite=$code',
    );
    await tap(tester, find.text('Join vault'));
    expect(find.text('Ops vault'), findsNothing);
    expect(find.textContaining('no longer accepted'), findsOneWidget);
    await tester.enterText(
      find.byType(TextField),
      'https://example.test/#invite=$code',
    );
    await tap(tester, find.text('Join vault'));
    expect(find.text('Ops vault'), findsNothing);
    expect(find.textContaining('only reads invite links'), findsOneWidget);
    await tester.enterText(
      find.byType(TextField),
      '${api.coordinator}/#invite=$code',
    );
    await tester.pump();
    expect(find.text('Ops vault'), findsOneWidget);
    expect(find.text('Member 3'), findsOneWidget);
    expect(find.text('2 of 4 approvals'), findsOneWidget);
    expect(api.writes.where((e) => e.$1 == 'join'), isEmpty);
    await tap(tester, find.text('Join vault'));
    expect(api.writes.singleWhere((e) => e.$1 == 'join').$2, {'invite': code});
    expect(find.text('Set up vault'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('Send draft discard takes a separate inline confirmation', (
    tester,
  ) async {
    final api = FixtureWallet();
    await start(tester, api);
    await tap(tester, find.text('Studio vault').first);
    await tap(tester, find.text('Send'));
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), FixtureWallet.recipient);
    await tester.enterText(fields.at(1), '1');
    await tap(tester, find.text('Prepare draft'));
    await tap(tester, find.text('Edit details'));
    expect(find.text('Discard this draft?'), findsOneWidget);
    expectInline(tester);
    expect(api.writes.where((e) => e.$1 == 'payment-discard'), isEmpty);
    await tap(tester, find.text('Go back'));
    expect(find.text('Request approvals'), findsOneWidget);
    await tap(tester, find.text('Edit details'));
    await tap(tester, find.text('Discard draft'));
    expect(api.writes.singleWhere((e) => e.$1 == 'payment-discard').$2, {
      'vault': FixtureWallet.studio,
      'attempt': 'd' * 64,
    });
    expect(find.text('Prepare draft'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'History confirm keeps exact transaction and replacement targets',
    (tester) async {
      final api = FixtureWallet()
        ..confirmed = false
        ..failed = true;
      await start(tester, api);
      await tap(tester, find.text('History').first);
      await tap(tester, find.text('Failed'));
      await tap(tester, find.text('Discard payment'));
      expect(find.text('Discard failed payment'), findsOneWidget);
      expect(find.text('Releases the reserved input'), findsOneWidget);
      expect(find.text(FixtureWallet.recipient), findsOneWidget);
      expect(find.text('TRANSACTIONS'), findsNothing);
      await tap(tester, find.text('Keep payment'));
      expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
      expect(api.writes.where((e) => e.$1 == 'payment-discard'), isEmpty);
      await tap(tester, find.text('Discard payment'));
      await tap(tester, find.text('Discard'));
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-discard').$2, {
        'vault': FixtureWallet.studio,
        'attempt': FixtureWallet.proposal,
      });
      await tap(tester, find.text('Awaiting confirmation'));
      await tap(tester, find.text('Send again'));
      expect(find.text('Send the same transaction again'), findsOneWidget);
      expect(find.text('Broadcast is not confirmation'), findsOneWidget);
      expect(find.text('TRANSACTIONS'), findsNothing);
      expectInline(tester);
      expect(find.text(FixtureWallet.txid), findsNothing);
      await tap(tester, find.text('Transaction reference'));
      expect(find.text(FixtureWallet.txid), findsOneWidget);
      expect(find.byTooltip('Copy transaction id'), findsNothing);
      expect(find.text('View on ZecBlock'), findsNothing);
      await tap(tester, find.text('Cancel'));
      expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
      expect(api.writes.where((e) => e.$1 == 'payment-send'), isEmpty);
      await tap(tester, find.text('Send again'));
      await tap(tester, find.text('Send again'));
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-send').$2, {
        'vault': FixtureWallet.studio,
        'attempt': FixtureWallet.sent,
      });

      await tap(tester, find.text('Request cancellation'));
      expect(find.text('Request cancellation'), findsOneWidget);
      expect(
        find.text('The original payment may confirm first'),
        findsOneWidget,
      );
      expect(find.text(FixtureWallet.sent), findsOneWidget);
      expect(find.text('e' * 64), findsOneWidget);
      expect(find.text('0.59990000 TAZ'), findsOneWidget);
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-replace').$2, {
        'vault': FixtureWallet.studio,
        'attempt': FixtureWallet.sent,
        'mode': 'cancel',
      });
      expect(api.writes.where((e) => e.$1 == 'payment-publish'), isEmpty);
      await tap(tester, find.text('Discard draft'));
      expect(api.writes.lastWhere((e) => e.$1 == 'payment-discard').$2, {
        'vault': FixtureWallet.studio,
        'attempt': 'e' * 64,
      });
      await tap(tester, find.text('Retry payment'));
      expect(find.text('Retry payment'), findsOneWidget);
      await tap(tester, find.text('Request approvals'));
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-publish').$2, {
        'vault': FixtureWallet.studio,
        'attempt': 'e' * 64,
      });
      expect(find.text('Review proposal'), findsOneWidget);
      expect(api.writes.where((e) => e.$1 == 'payment-approve'), isEmpty);
      await tap(tester, find.text('Back'));
      expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('Signed payment review stops a send after History confirms it', (
    tester,
  ) async {
    final api = FixtureWallet()
      ..confirmed = false
      ..broadcast = false;
    await start(tester, api, theme: ThemeMode.dark);
    await tap(tester, find.text('History').first);
    await tap(tester, find.text('Signed · not sent yet'));
    await tap(tester, find.text('Send now'));
    expect(find.text('Send signed payment'), findsOneWidget);
    expect(find.text('0.12000000 TAZ'), findsOneWidget);
    expect(api.writes.where((e) => e.$1 == 'payment-send'), isEmpty);

    api.confirmed = true;
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Send now'))
          .onPressed,
      isNull,
    );
    await tap(tester, find.text('Cancel'));
    expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
    expect(find.text(FixtureWallet.txid), findsOneWidget);
    expect(api.writes.where((e) => e.$1 == 'payment-send'), isEmpty);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'Native visibility and navigation win against late preview replies',
    (tester) async {
      final wallet = FixtureWallet();
      final snapshot = Completer<bool>();
      final leave = Completer<void>();
      final approve = Completer<void>();
      var leaves = 0;
      _mockMac(wallet, {
        'nativePromptActive': () => snapshot.future,
        'nativeNotice': () => null,
        'leaveNativePrompt': () {
          leaves++;
          return leave.future;
        },
        'payment-approve': () => approve.future,
      });
      await start(tester, const MacWalletApi());
      await _nativePromptChanged(true);
      snapshot.complete(false);
      await tester.pump();
      expect(find.text('Create vault'), findsNothing);
      expect(find.text('TESTNET'), findsOneWidget);
      await _nativePromptChanged(false);
      await tester.pump();
      expect(find.text('Create vault'), findsOneWidget);
      await tap(tester, find.text('Studio vault').first);
      await tap(tester, find.text('Review'));
      await tap(tester, find.text('Continue to signer'));
      await tap(tester, find.text('History'));
      expect(find.text('Review proposal'), findsOneWidget);
      expect(leaves, 0);

      await _nativePromptChanged(true);
      await tester.pump();
      expect(find.text('Review proposal'), findsNothing);
      expect(find.text('TESTNET'), findsOneWidget);
      expect(find.text(wallet.coordinator), findsOneWidget);
      await tap(tester, find.text('History'));
      expect(leaves, 1);
      await _nativePromptChanged(false);
      await tester.pump();
      expect(find.text('TRANSACTIONS'), findsNothing);
      expect(find.text('Review proposal'), findsNothing);
      leave.complete();
      await tester.pump();
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      approve.complete();
      await tester.pump();
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('Approval requested'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'Recovery notice stays inline and lock can cancel the native page',
    (tester) async {
      final wallet = FixtureWallet(running: false);
      final recover = Completer<void>(), lock = Completer<void>();
      var canRecover = true;
      String? notice = 'This Mac cannot access the old profile key.';
      var recoveries = 0, locks = 0;
      _mockMac(wallet, {
        'nativePromptActive': () => false,
        'nativeNotice': () => notice,
        'profile': () async => {
          ...await wallet.profile(),
          'can_recover_wallet_key': canRecover,
        },
        'recoverWalletKey': () {
          recoveries++;
          return recover.future;
        },
        'lock': () {
          locks++;
          return lock.future;
        },
      });
      await start(tester, const MacWalletApi());
      expect(find.text(notice), findsOneWidget);
      expect(find.text('Unlock your signer'), findsOneWidget);
      expectInline(tester);
      final recovery = find.text('Review profile recovery');
      expect(recovery, findsOneWidget);
      expect(recoveries, 0);
      await tap(tester, recovery);
      expect(recoveries, 1);
      await _nativePromptChanged(true);
      await tester.pump();
      expect(find.text('Unlock your signer'), findsNothing);
      expect(recovery, findsNothing);
      final lockButton = find.byWidgetPredicate(
        (w) => w is IconButton && w.tooltip == 'Lock signer',
      );
      await tap(tester, lockButton);
      expect(locks, 1);
      expect(tester.widget<IconButton>(lockButton).onPressed, isNull);

      canRecover = false;
      notice = null;
      await _nativePromptChanged(false);
      recover.complete();
      lock.complete();
      await tester.pump();
      await tester.pump(const Duration(seconds: 3));
      expect(find.text('Unlock your signer'), findsOneWidget);
      expect(recovery, findsNothing);
      expect(
        find.text('This Mac cannot access the old profile key.'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'First launch sends only the entered pairing link to the native pairing flow',
    (tester) async {
      final api = FixtureWallet(running: false, fresh: true);
      await start(tester, api);
      expect(find.text('Set up your signer'), findsOneWidget);
      expect(find.text('TESTNET'), findsOneWidget);
      expect(find.text('Testnet funds only'), findsOneWidget);
      await tap(tester, find.text('Pair this Mac'));
      expect(find.text('01 / 03'), findsOneWidget);
      expect(api.pairLink, isNull);
      const link =
          'loki://pair?coordinator=https://other.example:8443&slot=2&challenge=one-use';
      await tester.enterText(find.byType(TextField), '  $link  ');
      await tester.pump();
      expect(api.pairLink, isNull);
      await tap(tester, find.text('Continue'));
      expect(api.pairLink, link);
      expect(find.text('All vaults'), findsWidgets);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'The unlocked workspace shows the active signer’s pinned origin without a switch control',
    (tester) async {
      final api = FixtureWallet();
      final original = api.coordinator;
      const next = 'https://second-coordinator.example:8443';
      final semantics = tester.ensureSemantics();
      await start(tester, api);
      expect(find.text('Studio vault'), findsWidgets);
      expect(find.byIcon(Icons.view_sidebar_outlined), findsNothing);
      expect(find.text('Secure Enclave'), findsNothing);
      expect(find.text('Testnet funds only'), findsNothing);
      expect(find.text('TESTNET'), findsOneWidget);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.text('Studio vault').first);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.text('Reserve vault').first);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.byTooltip('Lock signer'));
      expect(api.running, isFalse);
      expect(find.text('Studio vault'), findsNothing);
      expect(find.text('Paired coordinator'), findsNothing);
      expect(find.text(original), findsNothing);

      api.coordinator = next;
      await tap(tester, find.text('Unlock signer'));
      expect(find.text('Studio vault'), findsWidgets);
      expect(find.text(original), findsNothing);
      final displayedOrigin = find.text(next);
      expect(displayedOrigin, findsOneWidget);
      expect(
        tester
            .getSemantics(displayedOrigin)
            .getSemanticsData()
            .hasAction(SemanticsAction.tap),
        isFalse,
      );
      semantics.dispose();
      api.writes.clear();
      await tap(tester, displayedOrigin);
      expect(find.byType(TextField), findsNothing);
      expect(api.writes, isEmpty);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
