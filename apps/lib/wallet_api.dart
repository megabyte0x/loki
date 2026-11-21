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

String walletError(Object error) => switch (error) {
  PlatformException(:final message) =>
    message ?? 'The signer refused this operation.',
  FormatException(:final message) => message,
  _ => 'LokiSigner could not complete this operation. Try again.',
};
