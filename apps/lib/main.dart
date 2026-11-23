import 'dart:async';
import 'dart:ui' show ImageFilter;

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'design.dart';
import 'payments.dart';
import 'vaults.dart';
import 'vortex.dart';
import 'wallet_api.dart';

void main() => runApp(const LokiApp(api: MacWalletApi()));

/// TEMPORARY verbose diagnostics: stdout goes to the profile's verbose log (VerboseLog.swift
/// part of WalletChannel.swift). Remove before release.
// ignore: avoid_print
void verbose(String message) => print('[verbose] dart $message');

class LokiApp extends StatefulWidget {
  const LokiApp({
    super.key,
    required this.api,
    this.initialTheme = ThemeMode.system,
  });
  final WalletApi api;
  final ThemeMode initialTheme;

  @override
  State<LokiApp> createState() => _LokiAppState();
}

class _LokiAppState extends State<LokiApp> {
  late ThemeMode theme = widget.initialTheme;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'LokiSigner',
    debugShowCheckedModeBanner: false,
    theme: lokiTheme(false),
    darkTheme: lokiTheme(true),
    themeMode: theme,
    home: _Wallet(
      api: widget.api,
      theme: theme,
      setTheme: (mode) async {
        setState(() => theme = mode);
        await widget.api.appearance(mode.name);
      },
    ),
  );
}

enum _Page {
  vaults,
  create,
  join,
  overview,
  setup,
  send,
  approvals,
  history,
  receive,
  recovery,
}

class _Wallet extends StatefulWidget {
  const _Wallet({
    required this.api,
    required this.theme,
    required this.setTheme,
  });
  final WalletApi api;
  final ThemeMode theme;
  final Future<void> Function(ThemeMode) setTheme;

  @override
  State<_Wallet> createState() => _WalletState();
}

class _WalletState extends State<_Wallet> with WidgetsBindingObserver {
  WalletApi get api => widget.api;
  // A cancelled Touch ID prompt leaves the vault's key closed for this session. Ask again by
  // itself, but only while the window is in front: at most once a minute, and right away when
  // the member comes back to the window.
  DateTime touchIdAgainAfter = DateTime.fromMillisecondsSinceEpoch(0);
  bool appActive = true;
  MacWalletApi? get macApi => api is MacWalletApi ? api as MacWalletApi : null;
  Timer? timer;
  bool polling = false,
      busy = false,
      loaded = false,
      open = false,
      locking = false;
  bool? nativePrompt;
  bool leavingNativePrompt = false;
  bool get hideContent =>
      (nativePrompt ?? (macApi != null)) || leavingNativePrompt || locking;
  bool get canRecoverWalletKey =>
      macApi != null && profile['can_recover_wallet_key'] == true;
  bool get hasNativeFeedback => nativeStatus != null || canRecoverWalletKey;
  // The profile was written but the coordinator never accepted its registration.
  bool get pairingPending => profile['pairing_pending'] == true;
  bool get waitingForPreview =>
      previewRequestGeneration == generation && nativePrompt != true;
  int generation = 0;
  int? previewRequestGeneration;
  Json profile = {};
  List<Json> vaults = [], payments = [], addresses = [];
  // Per vault: the signer's background relay sync (`sync` on payments/pending).
  Map<String, Json> relaySync = {};
  List<({Json vault, Json payment})> approvals = [];
  Json ceremony = {}, recovery = {};
  Object? balance;
  String? vaultId,
      selection,
      actionError,
      loadError,
      dataError,
      scanError,
      nativeStatus,
      coordinator;
  DateTime nextScan = DateTime.fromMillisecondsSinceEpoch(0);
  final verifyUntil = <String, DateTime>{};
  bool scanning = false, enteringLink = false;
  String pairingLink = '';
  // An invite link that opened the app: taken from the native side once unlocked, then shown
  // in Join for review. Never persisted; a lock or leaving Join drops it.
  bool inviteWaiting = true;
  String? joinInvite, joinPrefill;
  // Remounts the create/join form; never derived from the invite, which is a bearer secret.
  int formSerial = 0;
  static const _formPages = {
    _Page.create,
    _Page.join,
    _Page.setup,
    _Page.send,
    _Page.recovery,
  };
  _Page page = _Page.vaults;
  _Page formBack = _Page.vaults;
  ({Json vault, String attempt})? review;

  Json? get vault => vaults.where((v) => v['vault'] == vaultId).firstOrNull;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (macApi case final mac?) unawaited(watchNativePrompt(mac));
    unawaited(poll());
  }

  Future<void> watchNativePrompt(MacWalletApi mac) async {
    var receivedEvent = false;
    mac.onNativePromptChanged(
      (active) {
        receivedEvent = true;
        if (mounted) setState(() => nativePrompt = active);
      },
      onInvite: () {
        inviteWaiting = true;
        unawaited(poll());
      },
    );
    var active = false;
    try {
      active = await mac.nativePromptActive();
    } on MissingPluginException {
      // Older native runners have no content-area callbacks.
    } on PlatformException catch (e) {
      if (mounted) setState(() => actionError = walletError(e));
    }
    if (mounted && !receivedEvent) setState(() => nativePrompt = active);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    timer?.cancel();
    macApi?.onNativePromptChanged(null);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    appActive = state == AppLifecycleState.resumed;
    verbose('app lifecycle: ${state.name}');
    if (appActive) {
      touchIdAgainAfter = DateTime.fromMillisecondsSinceEpoch(0);
      nextScan = DateTime.fromMillisecondsSinceEpoch(0);
    }
  }

  void resetSession() {
    generation++;
    open = false;
    page = _Page.vaults;
    review = null;
    vaults = [];
    approvals = [];
    addresses = [];
    payments = [];
    ceremony = {};
    recovery = {};
    balance = null;
    vaultId = selection = dataError = scanError = coordinator = null;
    joinInvite = joinPrefill = null;
    pairingLink = '';
    enteringLink = false;
    verifyUntil.clear();
    nextScan = DateTime.fromMillisecondsSinceEpoch(0);
  }

  Future<void> poll() async {
    if (polling || !mounted) return;
    polling = true;
    timer?.cancel();
    final epoch = generation;
    try {
      if (macApi case final mac?) {
        try {
          final notice = await mac.nativeNotice();
          if (mounted && notice != nativeStatus) {
            setState(() => nativeStatus = notice);
          }
        } on MissingPluginException {
          // Notices are optional on older native runners.
        } on PlatformException {
          // Failure to read an advisory notice must not block the wallet poll.
        }
      }
      final current = await api.profile();
      if (!mounted || locking || epoch != generation) return;
      if (current['can_recover_wallet_key'] !=
              profile['can_recover_wallet_key'] ||
          current['pairing_pending'] != profile['pairing_pending']) {
        setState(() => profile = current);
      }
      if (current['running'] != true) {
        setState(() {
          if (open) resetSession();
          profile = current;
          loaded = true;
          loadError = null;
        });
        return;
      }
      final status = await api.request('status');
      if (!mounted || locking || epoch != generation) return;
      if (status['phase'] != 'home' || status['network'] != 'testnet') {
        setState(() {
          if (open) resetSession();
          loaded = true;
          profile = current;
          loadError = status['network'] != 'testnet'
              ? 'This app only supports Zcash testnet.'
              : null;
        });
        return;
      }
      final list = jsonRows(status['vaults']);
      setState(() {
        profile = current;
        loaded = open = true;
        loadError = null;
        coordinator = status['paired_coordinator'] as String?;
        vaults = list;
        vaultId ??=
            (list.where((v) => v['active'] == true).firstOrNull ??
                    list.firstOrNull)?['vault']
                as String?;
        if (page == _Page.setup && vault?['active'] == true) {
          page = _Page.overview;
        }
      });
      if (inviteWaiting && !_formPages.contains(page)) {
        inviteWaiting = false;
        final taken = await api.pendingInvite();
        // A claim taken for a session that has since changed is dropped, not kept.
        if (!mounted || locking || epoch != generation) return;
        if (taken != null) joinInvite = taken;
      }
      if (joinInvite != null &&
          !_formPages.contains(page) &&
          !busy &&
          !hideContent) {
        unawaited(go(_Page.join, invite: joinInvite));
        return;
      }
      final active = vault?['active'] == true;
      final id = vaultId;
      final view = page;
      if (id != null &&
          active &&
          view == _Page.overview &&
          DateTime.now().isAfter(nextScan)) {
        unawaited(scan(id, epoch));
      }
      // Fetch the selected vault's data first; another vault's relay can't stall setup.
      if (id != null && view == _Page.setup && !active) {
        final result = await api.request('status?vault=$id');
        if (mounted && epoch == generation) {
          setState(() {
            ceremony = result;
            dataError = null;
          });
        }
      } else if (id != null &&
          active &&
          (view == _Page.history || view == _Page.overview)) {
        final reply = await api.request('payments?vault=$id');
        final result = jsonRows(reply['payments']);
        if (!mounted || epoch != generation) return;
        setState(() {
          payments = result;
          if (reply['sync'] case final Json sync) relaySync[id] = sync;
          dataError = null;
        });
        if (!scanning) unawaited(verifyBroadcast(id, result));
      }
      if (id != null && active && view == _Page.recovery) {
        final result = await api.request('recovery-status?vault=$id');
        if (mounted && epoch == generation) {
          setState(() {
            recovery = result;
            dataError = null;
          });
        }
      }
      if (view == _Page.approvals ||
          view == _Page.overview ||
          view == _Page.vaults) {
        final inbox = await Future.wait(
          list.where((v) => v['active'] == true).map((v) async {
            final rows = await api.request('pending?vault=${v['vault']}');
            if (rows['sync'] case final Json sync) {
              relaySync[v['vault'] as String] = sync;
            }
            return jsonRows(rows['pending']).map((p) => (vault: v, payment: p));
          }),
        );
        if (mounted && epoch == generation) {
          setState(() {
            approvals = inbox.expand((rows) => rows).toList();
            dataError = null;
          });
        }
      }
    } catch (e) {
      if (!mounted || locking || epoch != generation) return;
      if (e is PlatformException && e.code == '401') {
        setState(resetSession);
      } else {
        setState(() {
          loaded = true;
          if (open) {
            dataError = walletError(e);
          } else {
            loadError = walletError(e);
          }
        });
      }
    } finally {
      polling = false;
      if (mounted) timer = Timer(const Duration(seconds: 2), poll);
    }
  }

  Future<void> scan(String id, int epoch, {bool retryTouchId = false}) async {
    if (scanning) return;
    scanning = true;
    nextScan = DateTime.now().add(const Duration(seconds: 10));
    var askAgain = false;
    try {
      final result = await api.request('balance', {
        'vault': id,
        if (retryTouchId) 'retry_touch_id': true,
      });
      if (mounted && epoch == generation) {
        setState(() {
          balance = result['balance_zat'];
          scanError = null;
          dataError = null;
        });
      }
    } catch (e) {
      final touchId = walletErrorCode(e) == 'touch_id_required';
      // TEMPORARY verbose diagnostics (stdout goes to the profile's verbose log).
      verbose(
        'balance scan failed (retry=$retryTouchId, active=$appActive): ${walletError(e)}',
      );
      askAgain =
          touchId &&
          !retryTouchId &&
          appActive &&
          DateTime.now().isAfter(touchIdAgainAfter);
      if (askAgain) {
        verbose('asking for Touch ID again to open the vault');
        touchIdAgainAfter = DateTime.now().add(const Duration(minutes: 1));
      } else if (mounted && epoch == generation) {
        setState(
          () => scanError = touchId
              ? 'Touch ID is needed to open this vault. LokiSigner will ask again.'
              : 'Balance could not sync. Retrying…',
        );
      }
    } finally {
      scanning = false;
    }
    // The vault is closed only because a Touch ID prompt was cancelled: prompt again now.
    if (askAgain && mounted && epoch == generation) {
      await scan(id, epoch, retryTouchId: true);
    }
  }

  Future<void> verifyBroadcast(String id, List<Json> result) async {
    final now = DateTime.now();
    final waiting = result.where(
      (p) => p['phase'] == 'broadcast' && p['txid'] != null,
    );
    final payment = waiting
        .where(
          (p) => verifyUntil
              .putIfAbsent(
                '$id/${p['attempt']}',
                () => now.add(const Duration(minutes: 1)),
              )
              .isAfter(now),
        )
        .firstOrNull;
    if (payment == null) return;
    scanning = true;
    try {
      await api.request('payment-verify', {
        'vault': id,
        'attempt': payment['attempt'],
        'txid': payment['txid'],
      });
    } catch (_) {
      // A missing confirmation is expected on testnet. History must keep 'Broadcast'.
    } finally {
      scanning = false;
    }
  }

  Future<void> go(
    _Page next, {
    String? id,
    String? attempt,
    String? invite,
  }) async {
    if (!mounted ||
        locking ||
        leavingNativePrompt ||
        waitingForPreview ||
        (macApi != null && nativePrompt == null)) {
      return;
    }
    if (macApi case final mac? when nativePrompt == true) {
      final epoch = generation;
      setState(() => leavingNativePrompt = true);
      try {
        await mac.leaveNativePrompt();
      } catch (e) {
        if (mounted && epoch == generation) {
          setState(() => actionError = walletError(e));
        }
        return;
      } finally {
        if (mounted) setState(() => leavingNativePrompt = false);
      }
      if (!mounted || locking || epoch != generation) return;
    }
    setState(() {
      generation++;
      actionError = dataError = null;
      review = null;
      if (id != null && id != vaultId) {
        vaultId = id;
        balance = null;
        payments = [];
        ceremony = recovery = {};
        scanError = null;
        nextScan = DateTime.fromMillisecondsSinceEpoch(0);
      }
      if (next == _Page.history && page != _Page.history) verifyUntil.clear();
      if (next == _Page.create || next == _Page.join) formBack = page;
      if (invite != null) joinInvite = null;
      joinPrefill = invite;
      if (next == _Page.create || next == _Page.join) formSerial++;
      page = next;
      selection = attempt;
    });
    unawaited(poll());
  }

  Future<void> act(Future<void> Function() perform) async {
    if (busy || hideContent) return;
    final epoch = generation;
    setState(() {
      busy = true;
      actionError = null;
      nativeStatus = null;
    });
    try {
      await perform();
    } catch (e) {
      if (mounted && epoch == generation) {
        setState(() => actionError = walletError(e));
      }
    } finally {
      if (mounted) {
        setState(() => busy = false);
        unawaited(poll());
      }
    }
  }

  Future<void> lock() async {
    if (locking || (busy && !hideContent)) return;
    setState(() {
      generation++;
      locking = true;
      actionError = nativeStatus = null;
    });
    try {
      await api.lock();
    } catch (e) {
      if (mounted) setState(() => actionError = walletError(e));
    } finally {
      if (mounted) {
        setState(() {
          resetSession();
          locking = false;
        });
        unawaited(poll());
      }
    }
  }

  void showReview(Json target, String attempt) {
    if (!mounted || hideContent || review != null) return;
    setState(() {
      generation++;
      actionError = null;
      review = (vault: target, attempt: attempt);
    });
  }

  Future<Json> requestReview(int epoch, String path, Json? body) async {
    if (path != 'payment-approve') return api.request(path, body);
    if (epoch != generation || hideContent) {
      throw StateError('The payment preview is no longer active.');
    }
    if (macApi == null) return api.request(path, body);
    // Wait for the native page to open before allowing navigation to cancel it.
    setState(() => previewRequestGeneration = epoch);
    try {
      return await api.request(path, body);
    } finally {
      if (mounted && previewRequestGeneration == epoch) {
        setState(() => previewRequestGeneration = null);
      }
    }
  }

  void openVault(Json v) => go(
    v['active'] == true ? _Page.overview : _Page.setup,
    id: v['vault'] as String,
  );

  Future<void> loadAddresses() => act(() async {
    final epoch = generation;
    final rows = await api.addresses();
    if (mounted && epoch == generation) setState(() => addresses = rows);
  });

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final still =
        hideContent ||
        review != null ||
        profile['reduce_motion'] == true ||
        page == _Page.send ||
        (page == _Page.history && selection != null);
    final fresh = profile['profile'] == 'fresh';
    return Scaffold(
      body: Stack(
        fit: StackFit.expand,
        children: [
          if (nativePrompt == true ||
              !open ||
              !{_Page.vaults, _Page.setup}.contains(page))
            Vortex(
              dark: c.dark,
              still: still || fresh,
              locked: !open && !fresh && nativePrompt != true,
            ),
          if (open)
            Row(
              children: [
                SizedBox(width: 204, child: sidebar()),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(26, 0, 26, 3),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        topBar(),
                        walletBody(
                          child: SingleChildScrollView(
                            key: ValueKey((
                              page,
                              vaultId,
                              review?.vault['vault'],
                              review?.attempt,
                            )),
                            padding: const EdgeInsets.only(top: 17, bottom: 12),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                if (hasNativeFeedback) ...[
                                  nativeFeedback(),
                                  const SizedBox(height: 12),
                                ],
                                content(),
                                if (actionError ?? dataError case final message?
                                    when message != nativeStatus) ...[
                                  const SizedBox(height: 12),
                                  Notice(message),
                                ],
                              ],
                            ),
                          ),
                        ),
                        if (syncLine() case final line?)
                          Padding(
                            padding: const EdgeInsets.only(top: 12),
                            child: line,
                          ),
                        if (coordinator case final origin?)
                          Padding(
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            child: Wrap(
                              spacing: 5,
                              crossAxisAlignment: WrapCrossAlignment.center,
                              children: [
                                Text(
                                  'Paired coordinator',
                                  style: lokiSans(10, color: c.muted),
                                ),
                                Text(
                                  origin,
                                  style: lokiMono(9, color: c.muted),
                                ),
                              ],
                            ),
                          ),
                      ],
                    ),
                  ),
                ),
              ],
            )
          else
            Row(
              children: [
                SizedBox(width: 204, child: sidebar(setup: true, fresh: fresh)),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(26, 0, 26, 3),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        topBar(),
                        walletBody(child: fresh ? signerSetup() : locked()),
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                'This Mac',
                                style: lokiSans(10, color: c.muted),
                              ),
                              Text(
                                'Testnet funds only',
                                style: lokiSans(10, color: c.muted),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
        ],
      ),
    );
  }

  // Retain in-flight Dart work without painting, focusing, or exposing its UI.
  Widget walletBody({required Widget child}) => Expanded(
    child: Visibility(visible: !hideContent, maintainState: true, child: child),
  );

  /// The current vault's relay sync, so a slow relay reads as "syncing", not a frozen app.
  Widget? syncLine() {
    final id = vaultId;
    final sync = id == null ? null : relaySync[id];
    if (sync == null) return null;
    final c = context.colors;
    final failing = sync['last_error'] != null;
    final last = sync['last_ok_at'];
    final String text;
    if (failing) {
      text = 'Relay unreachable. Retrying…';
    } else if (sync['in_progress'] == true && last == null) {
      text = 'Syncing with the relay…';
    } else if (last is int) {
      final age = DateTime.now().millisecondsSinceEpoch ~/ 1000 - last;
      text = age < 5
          ? 'Up to date'
          : 'Updated ${age < 60 ? '${age}s' : '${age ~/ 60} min'} ago';
    } else {
      text = 'Syncing with the relay…';
    }
    return Row(
      spacing: 6,
      children: [
        Icon(
          failing ? Icons.cloud_off_outlined : Icons.sync,
          size: 12,
          color: failing ? c.gold : c.muted,
        ),
        Text(text, style: lokiSans(10, color: failing ? c.gold : c.muted)),
      ],
    );
  }

  Widget nativeFeedback() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    spacing: 8,
    children: [
      if (nativeStatus case final message?) Notice(message),
      if (canRecoverWalletKey)
        ActionChipButton(
          'Review profile recovery',
          Icons.key_outlined,
          busy ? null : () => act(macApi!.recoverWalletKey),
        ),
    ],
  );

  Widget appearance() => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: Semantics(
      label: 'Appearance',
      child: SegmentedButton<ThemeMode>(
        showSelectedIcon: false,
        style: SegmentedButton.styleFrom(
          textStyle: lokiSans(10),
          visualDensity: VisualDensity.compact,
          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        ),
        segments: const [
          ButtonSegment(value: ThemeMode.system, label: Text('System')),
          ButtonSegment(value: ThemeMode.light, label: Text('Light')),
          ButtonSegment(value: ThemeMode.dark, label: Text('Dark')),
        ],
        selected: {widget.theme},
        onSelectionChanged: busy || hideContent
            ? null
            : (modes) => act(() => widget.setTheme(modes.single)),
      ),
    ),
  );

  Widget lockControl() => IconButton(
    onPressed: locking || (busy && !hideContent) ? null : lock,
    tooltip: 'Lock signer',
    icon: Icon(Icons.lock_outline, size: 15, color: context.colors.muted),
  );

  Widget topBar() {
    final c = context.colors;
    return SizedBox(
      height: 43,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          if (nativePrompt != true) appearance(),
          Surface(
            radius: 14,
            color: c.panel.withValues(alpha: .85),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
            child: Row(
              children: [
                Icon(Icons.circle, size: 5, color: c.mint),
                const SizedBox(width: 7),
                Text('TESTNET', style: lokiMono(9, spacing: 1.1)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget sidebar({bool setup = false, bool fresh = false}) {
    final c = context.colors;
    Widget caption(String text) => Padding(
      padding: const EdgeInsets.fromLTRB(11, 0, 0, 8),
      child: LokiLabel(text, color: c.muted),
    );
    Widget nav(
      String title,
      IconData icon,
      bool selected,
      VoidCallback? onTap, {
      int count = 0,
    }) => Semantics(
      selected: selected,
      child: Material(
        color: selected
            ? c.mint.withValues(alpha: c.dark ? .13 : .11)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(9),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: waitingForPreview ? null : onTap,
          child: Container(
            height: 35,
            padding: const EdgeInsets.symmetric(horizontal: 11),
            child: Row(
              children: [
                Icon(icon, size: 16, color: selected ? c.mint : c.muted),
                const SizedBox(width: 11),
                Expanded(
                  child: Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: lokiSans(12, weight: selected ? 600 : 500),
                  ),
                ),
                if (count > 0)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 6,
                      vertical: 3,
                    ),
                    decoration: BoxDecoration(
                      color: c.gold.withValues(alpha: .12),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text('$count', style: lokiMono(9, color: c.gold)),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
    final systemGlass = profile['liquid_glass'] == true;
    return Padding(
      padding: const EdgeInsets.all(8),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(17),
        child: Stack(
          fit: StackFit.expand,
          children: [
            if (systemGlass)
              const IgnorePointer(
                child: AppKitView(viewType: 'cash.loki/sidebar-glass'),
              ),
            BackdropFilter(
              enabled: !systemGlass,
              filter: ImageFilter.blur(sigmaX: 22, sigmaY: 22),
              child: DecoratedBox(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(17),
                  border: Border.all(color: c.stroke),
                  gradient: systemGlass
                      ? null
                      : LinearGradient(
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                          colors: [
                            (c.dark ? c.panel : Colors.white).withValues(
                              alpha: .76,
                            ),
                            c.bg.withValues(alpha: .86),
                          ],
                        ),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Expanded(
                        child: SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              Padding(
                                padding: const EdgeInsets.only(
                                  top: 46,
                                  left: 11,
                                ),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Brand(),
                                    const SizedBox(height: 4),
                                    Text(
                                      'Shielded multisig',
                                      style: lokiSans(12, color: c.muted),
                                    ),
                                  ],
                                ),
                              ),
                              const SizedBox(height: 30),
                              if (setup) ...[
                                caption('On this Mac'),
                                nav(
                                  'Signer setup',
                                  Icons.laptop_mac,
                                  fresh,
                                  null,
                                ),
                                nav(
                                  'Local profile',
                                  Icons.lock_outline,
                                  !fresh,
                                  null,
                                ),
                                nav(
                                  'Recovery',
                                  Icons.key_outlined,
                                  false,
                                  null,
                                ),
                              ] else ...[
                                caption('Workspace'),
                                nav(
                                  'All vaults',
                                  Icons.layers_outlined,
                                  page == _Page.vaults,
                                  () => go(_Page.vaults),
                                ),
                                nav(
                                  'Approvals',
                                  Icons.inbox_outlined,
                                  page == _Page.approvals,
                                  () => go(_Page.approvals),
                                  count: approvals.length,
                                ),
                                nav(
                                  'History',
                                  Icons.history,
                                  page == _Page.history,
                                  () => go(_Page.history),
                                ),
                                const SizedBox(height: 22),
                                caption('Vaults'),
                                for (final v in vaults)
                                  nav(
                                    vaultName(v),
                                    v['active'] == true
                                        ? Icons.lock_outline
                                        : Icons.pending_outlined,
                                    v['vault'] == vaultId &&
                                        {
                                          _Page.overview,
                                          _Page.setup,
                                          _Page.send,
                                        }.contains(page),
                                    () => openVault(v),
                                  ),
                                const SizedBox(height: 22),
                                caption('Signer'),
                                nav(
                                  'Vault addresses',
                                  Icons.qr_code,
                                  page == _Page.receive,
                                  () => go(_Page.receive),
                                ),
                                nav(
                                  'Recovery',
                                  Icons.key_outlined,
                                  page == _Page.recovery,
                                  () => go(_Page.recovery),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ),
                      const Divider(),
                      const SizedBox(height: 11),
                      Row(
                        children: [
                          CircleAvatar(
                            radius: 16,
                            backgroundColor: c.secondary,
                            child: Icon(
                              setup ? Icons.laptop_mac : Icons.person_outline,
                              color: c.ink,
                              size: 17,
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  setup
                                      ? 'LokiSigner'
                                      : profile['slot'] == null
                                      ? 'Member'
                                      : 'Member ${profile['slot']}',
                                  style: lokiSans(12, weight: 600),
                                ),
                                Text(
                                  'This Mac',
                                  style: lokiSans(10, color: c.muted),
                                ),
                              ],
                            ),
                          ),
                          if (!setup || nativePrompt == true || locking)
                            lockControl()
                          else
                            Icon(Icons.lock_outline, color: c.muted, size: 17),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget signerSetup() {
    final c = context.colors;
    return SingleChildScrollView(
      padding: const EdgeInsets.only(top: 16, bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 14,
        children: [
          LokiHead(
            'Signer setup',
            enteringLink ? 'Enter pairing link' : 'Set up your signer',
            enteringLink
                ? 'Paste the one-use pairing link your coordinator issued for this member slot.'
                : 'Pair a new signer with this Mac, or recover an existing signer.',
          ),
          Surface(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              spacing: 12,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: LokiLabel(
                        enteringLink ? 'Pairing link' : 'Start on this Mac',
                      ),
                    ),
                    if (enteringLink)
                      Text('01 / 03', style: lokiMono(9, color: c.muted)),
                  ],
                ),
                if (enteringLink)
                  pairingLinkField()
                else ...[
                  Text(
                    '01   Pair a new signer',
                    style: lokiSans(14, weight: 600),
                  ),
                  Text(
                    'Use the one-use pairing link from your coordinator.',
                    style: lokiSans(12, color: c.muted),
                  ),
                  const Divider(),
                  Text(
                    '02   Restore instead',
                    style: lokiSans(14, weight: 600),
                  ),
                  Text(
                    'You’ll need 24 recovery words and the encrypted vault backup.',
                    style: lokiSans(12, color: c.muted),
                  ),
                ],
              ],
            ),
          ),
          Notice(
            enteringLink
                ? 'Next: check the coordinator and slot. Continue shows them before any request is sent.'
                : 'Adding or removing an enrolled fingerprint can make this Mac’s signer keys unusable. Keep your words and backup.',
          ),
          if (hasNativeFeedback) nativeFeedback(),
          if (actionError case final message? when message != nativeStatus)
            Notice(message),
          if (busy) const LinearProgressIndicator(minHeight: 2),
          Wrap(
            alignment: WrapAlignment.end,
            spacing: 8,
            children: [
              ActionChipButton(
                enteringLink ? 'Cancel' : 'Restore signer',
                enteringLink ? Icons.close : Icons.key_outlined,
                busy
                    ? null
                    : enteringLink
                    ? () => setState(() {
                        enteringLink = false;
                        pairingLink = '';
                        actionError = null;
                      })
                    : () => act(api.restore),
              ),
              ActionChipButton(
                enteringLink ? 'Continue' : 'Pair this Mac',
                Icons.arrow_forward,
                busy || (enteringLink && pairingLink.trim().isEmpty)
                    ? null
                    : enteringLink
                    ? submitPairingLink
                    : () => setState(() {
                        enteringLink = true;
                        actionError = null;
                      }),
                primary: true,
              ),
            ],
          ),
        ],
      ),
    );
  }

  /// The one place a pairing link is typed, for a fresh profile or one whose
  /// registration never finished. The link is one-use and is not kept.
  Widget pairingLinkField() => TextFormField(
    initialValue: pairingLink,
    autofocus: true,
    readOnly: busy,
    obscureText: true,
    autocorrect: false,
    enableSuggestions: false,
    style: lokiMono(13),
    onChanged: (text) => setState(() {
      pairingLink = text;
      actionError = null;
    }),
    decoration: const InputDecoration(
      hintText: 'Paste pairing link',
      prefixIcon: Icon(Icons.link, size: 17),
    ),
  );

  void submitPairingLink() {
    final link = pairingLink.trim();
    setState(() {
      pairingLink = '';
      enteringLink = false;
    });
    act(() => api.pair(link));
  }

  Widget unfinishedPairing() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    spacing: 10,
    children: [
      const Notice(
        'This Mac’s registration with the coordinator didn’t finish. If the pairing link expired, ask the wallet for a new link for the same slot and paste it here.',
      ),
      if (enteringLink) pairingLinkField(),
      Wrap(
        alignment: WrapAlignment.end,
        spacing: 8,
        runSpacing: 8,
        children: [
          if (macApi case final mac? when !enteringLink)
            ActionChipButton(
              'Remove this profile',
              Icons.delete_outline,
              busy ? null : () => act(mac.discardPendingProfile),
            ),
          if (enteringLink)
            ActionChipButton(
              'Cancel',
              Icons.close,
              busy
                  ? null
                  : () => setState(() {
                      enteringLink = false;
                      pairingLink = '';
                    }),
            ),
          ActionChipButton(
            enteringLink ? 'Continue' : 'Paste a new pairing link',
            Icons.link,
            busy || (enteringLink && pairingLink.trim().isEmpty)
                ? null
                : enteringLink
                ? submitPairingLink
                : () => setState(() {
                    enteringLink = true;
                    actionError = null;
                  }),
          ),
        ],
      ),
    ],
  );

  Widget locked() {
    final c = context.colors;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: SizedBox(
          width: 356,
          child: Surface(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Brand(),
                const SizedBox(height: 15),
                const LokiLabel('Shielded multisig'),
                const SizedBox(height: 14),
                Text(
                  !loaded
                      ? 'Opening LokiSigner…'
                      : pairingPending
                      ? 'Finish pairing'
                      : 'Unlock your signer',
                  style: lokiSans(26, weight: 600, spacing: -1),
                ),
                const SizedBox(height: 12),
                Text(
                  'Use your local profile passphrase to open LokiSigner on this Mac.',
                  style: lokiSans(13, color: c.muted),
                ),
                if (hasNativeFeedback) ...[
                  const SizedBox(height: 12),
                  nativeFeedback(),
                ],
                if (actionError ?? loadError case final message?
                    when message != nativeStatus) ...[
                  const SizedBox(height: 12),
                  Notice(message),
                ],
                if (loaded && pairingPending) ...[
                  const SizedBox(height: 12),
                  unfinishedPairing(),
                ],
                const SizedBox(height: 18),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Flexible(
                      child: Text(
                        'Testnet only',
                        style: lokiMono(9, color: c.muted),
                      ),
                    ),
                    const SizedBox(width: 6),
                    Flexible(
                      flex: 3,
                      child: ActionChipButton(
                        'Unlock signer',
                        Icons.lock_open,
                        busy || !loaded ? null : () => act(api.unlock),
                        primary: true,
                      ),
                    ),
                  ],
                ),
                if (busy)
                  const Padding(
                    padding: EdgeInsets.only(top: 12),
                    child: LinearProgressIndicator(minHeight: 2),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget content() {
    final epoch = generation;
    if (review case (:final vault, :final attempt)) {
      return PaymentReview(
        vault: vault,
        attempt: attempt,
        request: (path, [body]) => requestReview(epoch, path, body),
        close: () => go(page, attempt: selection),
      );
    }
    final target = vault;
    return switch (page) {
      _Page.vaults => VaultLibrary(
        vaults: vaults,
        open: openVault,
        busy: busy,
        create: () => go(_Page.create),
        join: () => go(_Page.join),
      ),
      _Page.create || _Page.join => VaultForm(
        key: ValueKey(formSerial),
        join: page == _Page.join,
        initialInvite: joinPrefill,
        coordinator: coordinator,
        busy: busy,
        cancel: () => go(formBack),
        submit: (form) => submitVaultForm(page == _Page.join, form),
      ),
      _Page.setup when target != null => VaultSetup(
        vault: target,
        status: ceremony,
        coordinator: coordinator,
        busy: busy,
        compare: () => act(() async {
          await api.request('agree', {
            'vault': vaultId,
            'fingerprint': ceremony['fingerprint'],
            'roster_code': ceremony['roster_code'],
          });
        }),
        startOver: () => go(_Page.create),
      ),
      _Page.send when target != null => SendPage(
        vault: target,
        request: api.request,
        back: () {
          if (epoch == generation && !hideContent) {
            unawaited(go(_Page.overview));
          }
        },
        published: (attempt) {
          if (epoch == generation && !hideContent) {
            unawaited(go(_Page.history, attempt: attempt));
          }
        },
      ),
      _Page.overview when target != null => overview(target),
      _Page.approvals => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const LokiHead(
            'Workspace',
            'Approvals',
            'Payments awaiting your approval.',
          ),
          const SizedBox(height: 22),
          if (approvals.isEmpty)
            const Notice('No payment proposals are waiting for you.'),
          for (final item in approvals) ...[
            proposal(item.vault, item.payment, showVault: true),
            const SizedBox(height: 9),
          ],
        ],
      ),
      _Page.history => HistoryPage(
        vault: target?['active'] == true ? target : null,
        payments: payments,
        selected: selection,
        select: (id) => setState(() => selection = id),
        request: api.request,
        explorer: api.explorer,
        review: (attempt) {
          if (target != null && epoch == generation) {
            showReview(target, attempt);
          }
        },
        refresh: poll,
      ),
      _Page.receive => receive(),
      _Page.recovery => recoveryPage(),
      _ => const Notice('Choose a vault from the sidebar.'),
    };
  }

  Future<void> submitVaultForm(bool join, Json form) => act(() async {
    final epoch = generation;
    final result = await api.request(join ? 'join' : 'create', form);
    if (mounted && epoch == generation && !hideContent) {
      await go(_Page.setup, id: result['vault'] as String);
    }
  });

  Widget overview(Json v) {
    final c = context.colors;
    final pending = approvals
        .where((a) => a.vault['vault'] == v['vault'])
        .toList();
    // The newest confirmed payments; History lists every record.
    final recent = payments
        .where((p) => p['phase'] == 'confirmed')
        .take(5)
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(child: LokiHead('Active vault', vaultName(v))),
            StatusPill(policy(v)),
          ],
        ),
        const SizedBox(height: 17),
        Container(
          height: 155,
          padding: const EdgeInsets.symmetric(horizontal: 23),
          decoration: BoxDecoration(
            border: Border.all(color: c.stroke),
            borderRadius: BorderRadius.circular(16),
            gradient: LinearGradient(
              stops: const [0, .32, .68, 1],
              colors: [
                c.panel,
                c.panel,
                c.panel.withValues(alpha: .50),
                c.panel.withValues(alpha: .10),
              ],
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const LokiLabel('Balance'),
              const SizedBox(height: 8),
              Row(
                crossAxisAlignment: CrossAxisAlignment.baseline,
                textBaseline: TextBaseline.alphabetic,
                children: [
                  Text(
                    balance == null ? '—' : amountTaz(balance),
                    style: lokiMono(40, bold: true, spacing: -2.7),
                  ),
                  const SizedBox(width: 9),
                  Text('TAZ', style: lokiMono(16, color: c.muted)),
                  if (scanError case final error?) ...[
                    const SizedBox(width: 12),
                    Flexible(
                      child: Text(error, style: lokiSans(11, color: c.muted)),
                    ),
                  ],
                ],
              ),
              const SizedBox(height: 9),
              Row(
                children: [
                  ActionChipButton(
                    'Send',
                    Icons.north_east,
                    () => go(_Page.send),
                    primary: true,
                  ),
                  const SizedBox(width: 8),
                  ActionChipButton(
                    'Receive',
                    Icons.south_west,
                    () => go(_Page.receive),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        Row(
          children: [
            const LokiLabel('Approvals'),
            const SizedBox(width: 8),
            if (pending.isNotEmpty)
              StatusPill('${pending.length} pending', pending: true),
          ],
        ),
        const SizedBox(height: 9),
        if (pending.isEmpty)
          const Notice('No approvals waiting for this vault.')
        else
          for (final item in pending.take(2)) ...[
            proposal(item.vault, item.payment),
            const SizedBox(height: 6),
          ],
        const SizedBox(height: 15),
        Row(
          children: [
            const LokiLabel('Recent history'),
            const Spacer(),
            TextButton(
              onPressed: () => go(_Page.history),
              child: const Text('View history ›'),
            ),
          ],
        ),
        if (recent.isEmpty)
          const Notice('No confirmed payments yet.')
        else
          Surface(
            child: Column(
              children: [
                for (final p in recent) ...[
                  if (p != recent.first) const Divider(indent: 55),
                  InkWell(
                    onTap: () =>
                        go(_Page.history, attempt: p['attempt'] as String),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 17,
                        vertical: 8,
                      ),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 15,
                            backgroundColor: c.secondary,
                            child: Icon(
                              p['direction'] == 'received'
                                  ? Icons.south_west
                                  : Icons.north_east,
                              size: 14,
                              color: c.muted,
                            ),
                          ),
                          const SizedBox(width: 11),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  p['direction'] == 'received'
                                      ? 'Received'
                                      : 'Sent',
                                  style: lokiSans(12, weight: 600),
                                ),
                                Text(
                                  shortId(
                                    (p['recipient'] as String?)?.isNotEmpty ==
                                            true
                                        ? p['recipient'] as String
                                        : p['txid'] as String? ?? '',
                                  ),
                                  style: lokiMono(9, color: c.muted),
                                ),
                              ],
                            ),
                          ),
                          const StatusPill('Confirmed'),
                          const SizedBox(width: 18),
                          Text(
                            '${amountTaz(p['amount_zat'])} TAZ',
                            style: lokiMono(11),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
      ],
    );
  }

  Widget proposal(Json v, Json p, {bool showVault = false}) {
    final c = context.colors;
    return Surface(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      child: Row(
        children: [
          CircleAvatar(
            radius: 18,
            backgroundColor: c.gold.withValues(alpha: .11),
            child: Icon(Icons.draw_outlined, color: c.gold, size: 17),
          ),
          const SizedBox(width: 13),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Payment proposal', style: lokiSans(13, weight: 600)),
                const SizedBox(height: 4),
                Text(
                  '${showVault ? '${vaultName(v)} · ' : ''}Proposed by Member ${p['proposer']}',
                  style: lokiSans(11, color: c.muted),
                ),
              ],
            ),
          ),
          Text(
            '${amountTaz(p['amount_zat'])} TAZ',
            style: lokiMono(13, bold: true, color: c.gold),
          ),
          const SizedBox(width: 15),
          ActionChipButton(
            'Review',
            Icons.arrow_forward,
            () => showReview(v, p['attempt'] as String),
          ),
        ],
      ),
    );
  }

  Widget receive() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const LokiHead(
        'Signer',
        'Vault addresses',
        'Receive addresses are verified by this Mac before copying.',
      ),
      const SizedBox(height: 20),
      Align(
        alignment: Alignment.centerLeft,
        child: ActionChipButton(
          'Verify addresses',
          Icons.shield_outlined,
          busy ? null : loadAddresses,
          primary: true,
        ),
      ),
      for (final row in addresses) ...[
        const SizedBox(height: 12),
        Surface(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                row['name'] as String? ?? 'Vault',
                style: lokiSans(15, weight: 600),
              ),
              const SizedBox(height: 8),
              if (row['address'] case final String address) ...[
                Text(
                  'Testnet · Member ${row['slot']}',
                  style: lokiSans(11, color: context.colors.muted),
                ),
                const SizedBox(height: 8),
                SelectableText(address, style: lokiMono(11)),
                const SizedBox(height: 12),
                CopyButton('Copy address', address, 'Address copied'),
              ] else
                Text(
                  describeError(null, row['error'] as String?) ??
                      'LokiSigner could not verify the receive address.',
                ),
            ],
          ),
        ),
      ],
    ],
  );

  Widget recoveryPage() {
    final v = vault;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const LokiHead(
          'Signer',
          'Recovery',
          'Keep each vault’s encrypted backup separate from your recovery words.',
        ),
        const SizedBox(height: 21),
        Surface(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const LokiLabel('Encrypted backup'),
              const SizedBox(height: 10),
              Text(
                v?['active'] == true
                    ? vaultName(v!)
                    : 'Choose an active vault to export a backup.',
              ),
              const SizedBox(height: 10),
              const Text(
                'The 24 words alone cannot recover a vault. Save the encrypted backup away from this Mac.',
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ActionChipButton(
                    'Export encrypted backup',
                    Icons.download_outlined,
                    !busy && recovery['recovery_backup'] == true && v != null
                        ? () =>
                              act(() => api.exportBackup(v['vault'] as String))
                        : null,
                    primary: true,
                  ),
                  ActionChipButton(
                    'Restore a vault',
                    Icons.key_outlined,
                    busy ? null : () => act(api.restore),
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class Brand extends StatelessWidget {
  const Brand({super.key});
  @override
  Widget build(BuildContext context) =>
      Text('LOKI', style: lokiSans(28, weight: 800, spacing: 5));
}
