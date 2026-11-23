import 'package:flutter/services.dart';

typedef Json = Map<String, dynamic>;
typedef Request = Future<Json> Function(String path, [Json? body]);

// Only wallet data crosses this boundary. Key material, session credentials,
// passphrases, recovery words, and signing decisions stay with the native signer.
abstract interface class WalletApi {
  Future<Json> profile();
  Future<Json> request(String path, [Json? body]);
  Future<void> unlock();
  Future<void> pair(String link);
  // One invite link that opened this app, taken once after unlock; null when none.
  Future<String?> pendingInvite();
  Future<void> restore();
  Future<void> lock();
  Future<List<Json>> addresses();
  Future<void> exportBackup(String vault);
  Future<void> explorer(String txid);
  Future<void> appearance(String mode);
}

class MacWalletApi implements WalletApi {
  const MacWalletApi();
  static const _channel = MethodChannel('cash.loki/wallet');

  Future<bool> nativePromptActive() async =>
      await _channel.invokeMethod<bool>('nativePromptActive') ?? false;
  Future<void> leaveNativePrompt() =>
      _channel.invokeMethod('leaveNativePrompt');
  Future<String?> nativeNotice() =>
      _channel.invokeMethod<String>('nativeNotice');
  Future<void> recoverWalletKey() => _channel.invokeMethod('recoverWalletKey');

  void onNativePromptChanged(
    void Function(bool)? onChanged, {
    void Function()? onInvite,
  }) {
    _channel.setMethodCallHandler(
      onChanged == null
          ? null
          : (call) async {
              if (call.method == 'inviteArrived' && onInvite != null) {
                return onInvite();
              }
              if (call.method != 'nativePromptChanged') {
                throw MissingPluginException();
              }
              final active = call.arguments;
              if (active is bool) onChanged(active);
            },
    );
  }

  @override
  Future<Json> profile() async => _map(await _channel.invokeMethod('profile'));
  @override
  Future<Json> request(String path, [Json? body]) async => _map(
    await _channel.invokeMethod('request', {'path': path, 'body': ?body}),
  );
  @override
  Future<void> unlock() => _channel.invokeMethod('unlock');
  @override
  Future<void> pair(String link) =>
      _channel.invokeMethod('pair', {'link': link});
  @override
  Future<String?> pendingInvite() async {
    try {
      return await _channel.invokeMethod<String>('pendingInvite');
    } on MissingPluginException {
      return null;
    }
  }

  @override
  Future<void> restore() => _channel.invokeMethod('restore');
  @override
  Future<void> lock() => _channel.invokeMethod('lock');
  @override
  Future<List<Json>> addresses() async =>
      jsonRows(await _channel.invokeMethod('addresses'));
  @override
  Future<void> exportBackup(String vault) =>
      _channel.invokeMethod('export', {'vault': vault});
  @override
  Future<void> explorer(String txid) =>
      _channel.invokeMethod('explorer', {'txid': txid});
  @override
  Future<void> appearance(String mode) =>
      _channel.invokeMethod('appearance', {'mode': mode});
}

// StandardMessageCodec returns Map<Object?, Object?>, including at nested levels.
dynamic _decode(Object? value) => switch (value) {
  Map() => <String, dynamic>{
    for (final entry in value.entries)
      entry.key as String: _decode(entry.value),
  },
  List() => value.map(_decode).toList(),
  _ => value,
};

Json _map(Object? value) => _decode(value) as Json;
List<Json> jsonRows(Object? value) =>
    value is List ? value.map(_map).toList() : [];

/// The host's stable code for one of its own error sentences, if it sent one.
String? walletErrorCode(Object error) => switch (error) {
  PlatformException(:final details) when details is String => details,
  _ => null,
};

/// One line to show for a failed request: our own sentence for a known code,
/// otherwise the signer's text after `sanitizeLine`.
String walletError(Object error) =>
    describeError(walletErrorCode(error), switch (error) {
      PlatformException(:final message) => message,
      FormatException(:final message) => message,
      _ => null,
    }) ??
    'LokiSigner could not complete this operation. Try again.';

/// Like [walletError], but an uncoded reason follows [lead] so the user still
/// knows which step failed.
String walletErrorWith(String lead, Object error) {
  final known = _errorSentences[walletErrorCode(error)];
  if (known != null) return known;
  final reason = walletError(error);
  return '$lead Reason: $reason';
}

const _errorSentences = <String, String>{
  'funds_pending_confirmation':
      'These funds are still waiting for confirmations. Try again after a few more blocks.',
  'no_single_note':
      'No single spendable note covers this amount plus the network fee. Send a smaller amount.',
  'insufficient_funds':
      'The vault does not have enough spendable funds for this amount plus the network fee.',
  'invalid_address': 'That is not a valid Orchard address for this network.',
  'invalid_amount': 'Enter an amount greater than zero.',
  'profile_locked': 'LokiSigner is locked. Unlock it and try again.',
  'enough_approved': 'Enough members have already approved this payment.',
  'approval_repeated':
      'This approval was already sent or the payment changed. Replace a failed attempt instead.',
};

const _failureSentences = <String, String>{
  'approval_timeout': 'Another member did not answer the payment request in time.',
  'refused': 'A member refused the payment.',
  'share_deadline': 'The signing round timed out waiting for members.',
};

/// Our sentence for a known [code], else the sanitized [text], else null.
String? describeError(String? code, String? text) {
  final known = _errorSentences[code];
  if (known != null) return known;
  if (text == null) return null;
  final line = sanitizeLine(text);
  return line.isEmpty ? null : line;
}

/// Why a payment failed: our sentence for its `failure_reason`, else its
/// sanitized `error` text, else null.
String? paymentFailure(Json? payment) {
  if (payment == null) return null;
  final reason = payment['failure_reason'];
  if (reason is String && _failureSentences[reason] != null) {
    return _failureSentences[reason];
  }
  final error = payment['error'];
  return error is String ? describeError(null, error) : null;
}

/// Text from the signer, a relay, lightwalletd or another member, made safe for
/// one line: control, bidi, line-breaking and invisible characters become U+FFFD,
/// runs of combining marks are cut to three, and the result is at most [max]
/// characters. Mirrors `untrustedText` in the native signer.
String sanitizeLine(String text, {int max = 160}) {
  final out = StringBuffer();
  var marks = 0, length = 0;
  for (final rune in text.trim().runes) {
    if (length >= max) {
      out.write('…');
      break;
    }
    if (_hidden(rune)) {
      out.writeCharCode(0xFFFD);
      marks = 0;
    } else if (_combining(rune)) {
      if (++marks > 3) continue;
      out.writeCharCode(rune);
    } else {
      out.writeCharCode(rune);
      marks = 0;
    }
    length++;
  }
  return out.toString();
}

bool _hidden(int r) =>
    r < 0x20 ||
    (r >= 0x7F && r <= 0x9F) ||
    r == 0x00AD ||
    r == 0x034F ||
    r == 0x061C ||
    r == 0x115F ||
    r == 0x1160 ||
    r == 0x17B4 ||
    r == 0x17B5 ||
    (r >= 0x180B && r <= 0x180F) ||
    (r >= 0x200B && r <= 0x200F) ||
    (r >= 0x2028 && r <= 0x202E) ||
    (r >= 0x2060 && r <= 0x206F) ||
    r == 0x3164 ||
    (r >= 0xFE00 && r <= 0xFE0F) ||
    r == 0xFEFF ||
    r == 0xFFA0 ||
    (r >= 0xFFF0 && r <= 0xFFFB) ||
    (r >= 0x1BCA0 && r <= 0x1BCA3) ||
    (r >= 0x1D173 && r <= 0x1D17A) ||
    (r >= 0xE0000 && r <= 0xE0FFF);

bool _combining(int r) =>
    (r >= 0x0300 && r <= 0x036F) ||
    (r >= 0x1AB0 && r <= 0x1AFF) ||
    (r >= 0x1DC0 && r <= 0x1DFF) ||
    (r >= 0x20D0 && r <= 0x20FF) ||
    (r >= 0xFE20 && r <= 0xFE2F);
