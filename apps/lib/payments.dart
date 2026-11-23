import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'design.dart';
import 'wallet_api.dart';

final _zatsPerTaz = BigInt.from(100000000);
final _maxZats = BigInt.from(21000000) * _zatsPerTaz;
final _decimal = RegExp(r'^[0-9]{1,8}(?:\.([0-9]{1,8}))?$');
final _nonDigit = RegExp(r'[^0-9]');
final _trailingZeros = RegExp(r'0+$');
final _hexId = RegExp(r'^[0-9a-fA-F]{64}$');

String? _amountZats(String input) {
  final match = _decimal.firstMatch(input);
  if (match == null || match.end != input.length) return null;
  final fraction = match.group(1) ?? '';
  final zats =
      BigInt.parse(input.split('.').first) * _zatsPerTaz +
      BigInt.parse(fraction.padRight(8, '0'));
  return zats > BigInt.zero && zats <= _maxZats ? zats.toString() : null;
}

BigInt? _readZats(Object? value) {
  if (value is int) return value >= 0 ? BigInt.from(value) : null;
  if (value is! String || value.isEmpty || _nonDigit.hasMatch(value)) {
    return null;
  }
  return BigInt.tryParse(value);
}

String amountTaz(Object? zats, {bool fixed = false}) {
  final value = _readZats(zats);
  if (value == null) return '—';
  final whole = value ~/ _zatsPerTaz;
  final digits = (value % _zatsPerTaz).toString().padLeft(8, '0');
  final fraction = fixed ? digits : digits.replaceFirst(_trailingZeros, '');
  return fraction.isEmpty ? '$whole' : '$whole.$fraction';
}

String _withUnit(Object? zats, {bool fixed = false}) {
  final value = amountTaz(zats, fixed: fixed);
  return value == '—' ? value : '$value TAZ';
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`, or null.
String? _utc(Object? seconds) {
  if (seconds is! int || seconds <= 0) return null;
  final t = DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
  String two(int n) => n.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}:${two(t.second)} UTC';
}

String? _text(Object? value) =>
    value is String && value.isNotEmpty ? value : null;
String? _id(Object? value) =>
    value is String && value.length == 64 && _hexId.hasMatch(value)
    ? value
    : null;
Json? _object(Object? value) => value is Json ? value : null;
String _vaultName(Json? vault) => _text(vault?['name']) ?? 'Vault';
String _short(String value) => value.length > 17
    ? '${value.substring(0, 10)}…${value.substring(value.length - 4)}'
    : value;

String? _policy(Json vault) {
  final required = vault['threshold'], members = vault['members'];
  if (required is int &&
      members is int &&
      required > 0 &&
      members >= required) {
    return '$required of $members';
  }
  return null;
}

bool _settled(Object? phase) => const {
  'confirmed',
  'replaced',
  'spent_unverified',
  'cancelled',
  'expired',
}.contains(phase);

String paymentPhase(Json payment) {
  final phase = payment['phase'];
  if (payment['sending'] == true && !_settled(phase) && phase != 'broadcast') {
    return 'Sending';
  }
  return switch (phase) {
    'draft' => 'Draft',
    'preparing' => 'Preparing payment',
    'signing' => 'Collecting approvals',
    'approved' => 'Approved · awaiting the signed transaction',
    'not_selected' => 'Other members are signing',
    'ready' => 'Signed · building the transaction',
    'signed' => 'Signed · not sent yet',
    'broadcast' => 'Awaiting confirmation',
    'confirmed' => 'Confirmed',
    'replaced' => 'Replaced',
    'spent_unverified' => 'Input spent · payment unverified',
    'failed' => 'Failed',
    'discarding' => 'Releasing reserved notes',
    'cancelled' => 'Cancelled',
    'expired' => 'Expired',
    _ => 'Status unavailable',
  };
}

Widget _phasePill(Json payment) => FittedBox(
  fit: BoxFit.scaleDown,
  alignment: Alignment.centerLeft,
  child: StatusPill(
    paymentPhase(payment),
    pending: payment['phase'] != 'confirmed',
  ),
);

class _PaymentNote extends StatelessWidget {
  const _PaymentNote(this.text, {this.error = false});
  final String text;
  final bool error;

  @override
  Widget build(BuildContext context) => Semantics(
    liveRegion: error,
    child: Text(
      text,
      style: TextStyle(
        fontSize: 12,
        height: 1.4,
        color: error ? context.colors.gold : context.colors.muted,
      ),
    ),
  );
}

class _ReviewNotice extends StatelessWidget {
  const _ReviewNotice(this.title, this.message, {this.warning = false});
  final String title, message;
  final bool warning;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final tint = warning ? c.gold : c.mint;
    return Surface(
      color: Color.alphaBlend(tint.withValues(alpha: .07), c.panel),
      padding: const EdgeInsets.all(14),
      radius: 12,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        spacing: 10,
        children: [
          Icon(
            warning ? Icons.warning_amber : Icons.info_outline,
            size: 17,
            color: tint,
          ),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              spacing: 4,
              children: [
                Text(title, style: lokiSans(12, weight: 600, color: tint)),
                _PaymentNote(message),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _PaymentDetails extends StatelessWidget {
  const _PaymentDetails(this.title, this.payment, this.vault);
  final String title;
  final Json payment, vault;

  @override
  Widget build(BuildContext context) {
    final recipient = _text(payment['recipient']),
        memo = _text(payment['memo']);
    final destination = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 8,
      children: [
        if (recipient != null) ...[
          LokiLabel('Recipient address', color: context.colors.muted),
          SelectableText(recipient, style: lokiMono(11).copyWith(height: 1.4)),
        ],
        if (memo != null) ...[
          LokiLabel('Memo (sender’s text)', color: context.colors.muted),
          SelectableText(memo, style: lokiSans(12)),
        ],
      ],
    );
    final quote = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 8,
      children: [
        ValueRow(
          'Amount',
          _withUnit(payment['amount_zat'], fixed: true),
          mono: true,
        ),
        if (_readZats(payment['fee_zat']) != null)
          ValueRow(
            'Network fee',
            _withUnit(payment['fee_zat'], fixed: true),
            mono: true,
          ),
        if (_readZats(payment['change_zat']) != null)
          ValueRow(
            'Change back to vault',
            _withUnit(payment['change_zat'], fixed: true),
            mono: true,
          ),
        ValueRow('Vault (creator’s label)', _vaultName(vault)),
        if (_policy(vault) case final policy?)
          ValueRow('Vault policy', '$policy approvals'),
      ],
    );
    return Surface(
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 11,
        children: [
          LokiLabel(title),
          if (recipient == null && memo == null)
            quote
          else
            LayoutBuilder(
              builder: (context, bounds) => bounds.maxWidth >= 550
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      spacing: 22,
                      children: [
                        Expanded(child: destination),
                        Expanded(child: quote),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      spacing: 11,
                      children: [destination, const Divider(), quote],
                    ),
            ),
        ],
      ),
    );
  }
}

class _AmountHeading extends StatelessWidget {
  const _AmountHeading(this.zats, {this.pending = false, this.size = 25});
  final Object? zats;
  final bool pending;
  final double size;

  @override
  Widget build(BuildContext context) {
    final value = amountTaz(zats);
    return Text.rich(
      TextSpan(
        children: [
          TextSpan(
            text: value,
            style: lokiMono(
              size,
              bold: true,
              color: pending ? context.colors.gold : context.colors.ink,
              spacing: -0.7,
            ),
          ),
          if (value != '—')
            TextSpan(
              text: ' TAZ',
              style: lokiMono(12, color: context.colors.muted),
            ),
        ],
      ),
    );
  }
}

class _Confirmation extends StatelessWidget {
  const _Confirmation({
    required this.title,
    required this.message,
    required this.action,
    required this.confirm,
    required this.cancel,
  });
  final String title, action;
  final Widget message;
  final VoidCallback confirm, cancel;

  @override
  Widget build(BuildContext context) => Surface(
    padding: const EdgeInsets.all(15),
    color: context.colors.secondary,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 10,
      children: [
        Text(title, style: lokiSans(16, weight: 600)),
        message,
        Wrap(
          alignment: WrapAlignment.end,
          spacing: 8,
          runSpacing: 8,
          children: [
            ActionChipButton('Go back', Icons.close, cancel),
            ActionChipButton(
              action,
              Icons.arrow_forward,
              confirm,
              primary: true,
            ),
          ],
        ),
      ],
    ),
  );
}

bool _hasQuote(Json quote) =>
    _readZats(quote['fee_zat']) != null &&
    _readZats(quote['change_zat']) != null;

class SendPage extends StatefulWidget {
  const SendPage({
    super.key,
    required this.vault,
    required this.request,
    required this.back,
    required this.published,
  });
  final Json vault;
  final Request request;
  final VoidCallback back;
  final ValueChanged<String> published;

  @override
  State<SendPage> createState() => _SendPageState();
}

class _SendPageState extends State<SendPage> {
  final _recipient = TextEditingController();
  final _amount = TextEditingController();
  final _memo = TextEditingController();
  Json? _draft;
  String? _busy, _error;
  bool? _editAfterDiscard;
  bool _publishUncertain = false;
  // What the vault can pay now, from the signer's local wallet (`balance`).
  Json? _funds;
  bool _fundsLoading = false, _fundsFailed = false;

  @override
  void initState() {
    super.initState();
    _loadFunds();
  }

  @override
  void didUpdateWidget(covariant SendPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.vault['vault'] == widget.vault['vault']) return;
    _recipient.clear();
    _amount.clear();
    _memo.clear();
    _draft = null;
    _busy = _error = null;
    _editAfterDiscard = null;
    _publishUncertain = false;
    _funds = null;
    _loadFunds();
  }

  Future<void> _loadFunds() async {
    final vault = _text(widget.vault['vault']);
    if (vault == null || _fundsLoading) return;
    setState(() => _fundsLoading = true);
    try {
      final funds = await widget.request('balance', {'vault': vault});
      if (!_current(vault)) return;
      setState(() {
        _funds = funds;
        _fundsFailed = false;
      });
    } catch (_) {
      if (_current(vault)) setState(() => _fundsFailed = true);
    } finally {
      if (_current(vault)) setState(() => _fundsLoading = false);
    }
  }

  /// Why the entered amount can't be funded right now, or null if it can or
  /// the amounts aren't known. The signer still decides when drafting.
  String? _fundingBlock() {
    final funds = _funds, entered = _amountZats(_amount.text);
    if (funds == null || entered == null) return null;
    final amount = BigInt.parse(entered),
        max = _readZats(funds['max_payment_zat']),
        fee = _readZats(funds['max_payment_fee_zat']) ?? BigInt.zero,
        spendable = _readZats(funds['spendable_zat']),
        total = _readZats(funds['balance_zat']),
        pending = _readZats(funds['pending_zat']) ?? BigInt.zero,
        reserved = _readZats(funds['reserved_zat']) ?? BigInt.zero;
    if (max == null || spendable == null || total == null) return null;
    if (amount <= max) return null;
    final needed = amount + fee;
    if (needed > total) {
      return 'This is more than the vault holds. With the network fee it needs ${_withUnit(needed.toString())}; the vault holds ${_withUnit(total.toString())}.';
    }
    if (needed > spendable) {
      final waiting = pending > BigInt.zero
          ? '${_withUnit(pending.toString())} is still waiting for ${funds['confirmations_required'] ?? 'more'} confirmations'
          : null;
      final held = reserved > BigInt.zero
          ? '${_withUnit(reserved.toString())} is held by an open payment'
          : null;
      final why = [waiting, held].whereType<String>().join(' and ');
      return 'Not spendable yet${why.isEmpty ? '' : ': $why'}. Spendable now: ${_withUnit(spendable.toString())}.';
    }
    final inputs = funds['max_inputs'];
    return inputs == 1
        ? 'No single note covers this amount plus the network fee. The largest payment right now is ${_withUnit(max.toString())}.'
        : 'A payment can combine at most $inputs notes. The largest payment right now is ${_withUnit(max.toString())}.';
  }

  @override
  void dispose() {
    _recipient.dispose();
    _amount.dispose();
    _memo.dispose();
    super.dispose();
  }

  bool _current(String vault) => mounted && widget.vault['vault'] == vault;

  Future<void> _prepare() async {
    final vault = _text(widget.vault['vault']);
    if (vault == null || _busy != null || _draft != null) return;
    final recipient = _recipient.text.trim(),
        amount = _amountZats(_amount.text),
        memo = _memo.text;
    final error = switch ((
      recipient.isEmpty || RegExp(r'\s').hasMatch(recipient),
      amount == null,
      utf8.encode(memo).length > 512,
    )) {
      (true, _, _) => 'Enter one recipient address without spaces.',
      (_, true, _) => 'Enter a positive amount up to 21 million TAZ, with no more than eight decimal places.',
      (_, _, true) => 'The memo must fit in 512 UTF-8 bytes.',
      _ => null,
    };
    if (error != null) {
      setState(() => _error = error);
      return;
    }
    setState(() {
      _busy = 'Preparing…';
      _error = null;
    });
    try {
      final draft = await widget.request('payment-draft', {
        'vault': vault,
        'recipient': recipient,
        'amount_zat': amount,
        'memo': memo,
      });
      if (!_current(vault)) return;
      if (_text(draft['attempt']) == null) throw const FormatException();
      setState(() {
        _draft = draft;
        if (!_hasQuote(draft)) _error = 'The signer did not return a complete quote. Discard the draft and prepare it again.';
      });
    } catch (e) {
      if (_current(vault)) {
        setState(
          () => _error = walletErrorWith('Could not prepare the payment.', e),
        );
        _loadFunds();
      }
    } finally {
      if (_current(vault)) setState(() => _busy = null);
    }
  }

  Future<void> _publish() async {
    final vault = _text(widget.vault['vault']),
        attempt = _text(_draft?['attempt']);
    if (vault == null ||
        attempt == null ||
        _busy != null ||
        !_hasQuote(_draft!)) {
      return;
    }
    setState(() {
      _busy = 'Requesting…';
      _error = null;
    });
    try {
      await widget.request('payment-publish', {
        'vault': vault,
        'attempt': attempt,
      });
      if (_current(vault)) widget.published(attempt);
    } catch (e) {
      if (_current(vault)) {
        setState(() {
          _publishUncertain = true;
          _error = walletErrorWith(
            'Could not confirm publication. Go back and check this payment in History before acting on it again.',
            e,
          );
        });
      }
    } finally {
      if (_current(vault)) setState(() => _busy = null);
    }
  }

  void _leaveDraft({required bool edit}) {
    if (_busy != null) return;
    if (_draft == null || _publishUncertain) {
      widget.back();
      return;
    }
    setState(() => _editAfterDiscard = edit);
  }

  Future<void> _discardDraft() async {
    final edit = _editAfterDiscard;
    final vault = _text(widget.vault['vault']),
        attempt = _text(_draft?['attempt']);
    if (_busy != null || edit == null || vault == null || attempt == null) {
      return;
    }
    setState(() {
      _busy = 'Discarding…';
      _editAfterDiscard = null;
    });
    try {
      await widget.request('payment-discard', {
        'vault': vault,
        'attempt': attempt,
      });
      if (!_current(vault)) return;
      setState(() {
        _draft = null;
        _error = null;
      });
      if (!edit) widget.back();
    } catch (e) {
      if (_current(vault)) {
        setState(
          () => _error = walletErrorWith(
            'Could not confirm that the draft was discarded. Check History.',
            e,
          ),
        );
      }
    } finally {
      if (_current(vault)) setState(() => _busy = null);
    }
  }

  Widget _field(
    String label,
    TextEditingController controller, {
    required String hint,
    bool mono = false,
    bool decimal = false,
    int lines = 1,
  }) {
    final colors = context.colors;
    final border = OutlineInputBorder(
      borderRadius: BorderRadius.circular(10),
      borderSide: BorderSide(color: colors.stroke),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 7,
      children: [
        Text(
          label,
          style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
        ),
        Semantics(
          label: label,
          child: TextField(
            controller: controller,
            readOnly: _draft != null || _busy != null,
            autocorrect: !mono,
            enableSuggestions: !mono,
            minLines: 1,
            maxLines: lines,
            keyboardType: decimal
                ? const TextInputType.numberWithOptions(decimal: true)
                : lines > 1
                ? TextInputType.multiline
                : TextInputType.text,
            style: mono
                ? lokiMono(12, color: colors.ink)
                : TextStyle(color: colors.ink, fontSize: 12),
            decoration: InputDecoration(
              isDense: true,
              hintText: hint,
              hintStyle: TextStyle(color: colors.muted),
              filled: true,
              fillColor: colors.secondary,
              enabledBorder: border,
              focusedBorder: border.copyWith(
                borderSide: BorderSide(color: colors.mint),
              ),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 11,
              ),
            ),
            onChanged: (_) => setState(() => _error = null),
          ),
        ),
      ],
    );
  }

  Widget _funding() {
    final funds = _funds;
    if (funds == null) {
      return _PaymentNote(
        _fundsFailed
            ? 'Could not read the spendable balance. The signer still checks funds when you prepare the draft.'
            : 'Reading the spendable balance…',
        error: _fundsFailed,
      );
    }
    final spendable = _readZats(funds['spendable_zat']),
        total = _readZats(funds['balance_zat']),
        pending = _readZats(funds['pending_zat']) ?? BigInt.zero,
        reserved = _readZats(funds['reserved_zat']) ?? BigInt.zero,
        max = _readZats(funds['max_payment_zat']);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 8,
      children: [
        ValueRow('Spendable now', _withUnit(spendable?.toString()), mono: true),
        if (total != spendable)
          ValueRow('Total balance', _withUnit(total?.toString()), mono: true),
        if (pending > BigInt.zero)
          _PaymentNote(
            '${_withUnit(pending.toString())} waiting for ${funds['confirmations_required'] ?? 'more'} confirmations.',
          ),
        if (reserved > BigInt.zero)
          _PaymentNote(
            '${_withUnit(reserved.toString())} held by an open payment.',
          ),
        if (max != null && spendable != null && max < spendable)
          ValueRow('Largest payment now', _withUnit(max.toString()), mono: true),
        _PaymentNote(
          'As of block ${funds['scanned_height'] ?? '—'}, as reported by the chain provider.',
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final policy = _policy(widget.vault);
    final block = _draft == null ? _fundingBlock() : null;
    final details = Surface(
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 17,
        children: [
          const LokiLabel('Payment details'),
          _field(
            'Recipient address',
            _recipient,
            hint: 'Unified address',
            mono: true,
            lines: 4,
          ),
          _field(
            'Amount (TAZ)',
            _amount,
            hint: 'Enter amount',
            mono: true,
            decimal: true,
          ),
          _field('Memo (optional)', _memo, hint: 'Add a memo', lines: 4),
        ],
      ),
    );
    final summary = Surface(
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 12,
        children: [
          const LokiLabel('Transaction summary'),
          _AmountHeading(_amountZats(_amount.text), pending: true),
          const Divider(height: 1),
          _funding(),
          Align(
            alignment: Alignment.centerLeft,
            child: ActionChipButton(
              _fundsLoading ? 'Refreshing…' : 'Refresh balance',
              Icons.refresh,
              _fundsLoading || _busy != null ? null : _loadFunds,
            ),
          ),
          const Divider(height: 1),
          ValueRow('Network fee', _withUnit(_draft?['fee_zat']), mono: true),
          ValueRow('Change', _withUnit(_draft?['change_zat']), mono: true),
          if (policy != null) ...[
            const Divider(height: 1),
            ValueRow('Policy', policy),
          ],
          _PaymentNote(
            _draft == null
                ? 'Prepare a draft to see the network fee and change. No proposal is shared yet.'
                : 'Funds move only after the required members approve and the payment is sent.',
          ),
        ],
      ),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 17,
      children: [
        LokiHead(
          _vaultName(widget.vault),
          'Send payment',
          'Prepare a proposal for the other members of this vault.',
        ),
        LayoutBuilder(
          builder: (context, bounds) => bounds.maxWidth >= 560
              ? Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  spacing: 15,
                  children: [
                    Expanded(child: details),
                    SizedBox(width: 251, child: summary),
                  ],
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  spacing: 15,
                  children: [details, summary],
                ),
        ),
        if (_error case final error?) _PaymentNote(error, error: true),
        if (block != null && _error == null) _PaymentNote(block, error: true),
        if (_editAfterDiscard != null)
          _Confirmation(
            title: 'Discard this draft?',
            message: const _PaymentNote(
              'This releases the draft’s reserved notes without sending it. You can prepare a new draft afterward.',
            ),
            action: 'Discard draft',
            confirm: _discardDraft,
            cancel: () => setState(() => _editAfterDiscard = null),
          )
        else
          Wrap(
            alignment: WrapAlignment.end,
            spacing: 8,
            runSpacing: 8,
            children: [
              ActionChipButton(
                _publishUncertain ? 'Back' : 'Cancel',
                Icons.close,
                _busy == null ? () => _leaveDraft(edit: false) : null,
              ),
              if (_draft != null && !_publishUncertain)
                ActionChipButton(
                  'Edit details',
                  Icons.edit_outlined,
                  _busy == null ? () => _leaveDraft(edit: true) : null,
                ),
              if (!_publishUncertain)
                ActionChipButton(
                  _busy ??
                      (_draft == null ? 'Prepare draft' : 'Request approvals'),
                  _draft == null ? Icons.arrow_forward : Icons.send_outlined,
                  _busy != null || _text(widget.vault['vault']) == null
                      ? null
                      : _draft == null
                      ? (block == null ? _prepare : null)
                      : _hasQuote(_draft!)
                      ? _publish
                      : null,
                  primary: true,
                ),
            ],
          ),
      ],
    );
  }
}

class HistoryPage extends StatefulWidget {
  const HistoryPage({
    super.key,
    required this.vault,
    required this.payments,
    required this.selected,
    required this.select,
    required this.request,
    required this.explorer,
    required this.review,
    required this.refresh,
  });
  final Json? vault;
  final List<Json> payments;
  final String? selected;
  final ValueChanged<String?> select;
  final Request request;
  final Future<void> Function(String txid) explorer;
  final ValueChanged<String> review;
  final VoidCallback refresh;

  @override
  State<HistoryPage> createState() => _HistoryPageState();
}

class _HistoryPageState extends State<HistoryPage> {
  bool _busy = false;
  String? _error, _errorAttempt, _copied;
  ({Json payment, String action, Json? draft})? _confirmation;
  final _reviewHeading = GlobalKey();

  void _openConfirmation(Json payment, String action, [Json? draft]) {
    setState(
      () => _confirmation = (payment: payment, action: action, draft: draft),
    );
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_reviewHeading.currentContext case final context?) {
        unawaited(Scrollable.ensureVisible(context));
      }
    });
  }

  @override
  void didUpdateWidget(covariant HistoryPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.selected != widget.selected ||
        oldWidget.vault?['vault'] != widget.vault?['vault']) {
      _error = _errorAttempt = _copied = null;
      _confirmation = null;
    }
  }

  Future<void> _action(
    Json payment,
    String action, {
    bool? confirmed,
    Json? draft,
  }) async {
    final vault = _text(widget.vault?['vault']),
        attempt = _text(payment['attempt']);
    if (_busy || vault == null || attempt == null) return;
    if (confirmed == null && (action == 'send' || action == 'discard')) {
      _error = null;
      _openConfirmation(payment, action);
      return;
    }
    final request = widget.request;
    final body = {'vault': vault, 'attempt': attempt};
    bool current() =>
        mounted &&
        widget.vault?['vault'] == vault &&
        widget.selected == attempt;
    setState(() {
      _busy = true;
      _error = null;
    });
    String? replacement;
    try {
      if (draft != null) {
        final id = _text(draft['attempt'])!;
        final next = {'vault': vault, 'attempt': id};
        if (confirmed == true) {
          await request('payment-publish', next);
          replacement = id;
        } else {
          await request('payment-discard', next);
        }
      } else if (confirmed == true) {
        await request(
          action == 'send' ? 'payment-send' : 'payment-discard',
          body,
        );
      } else {
        final draft = await request('payment-replace', {
          ...body,
          'mode': action,
        });
        final id = _text(draft['attempt']),
            recipient = _text(draft['recipient']);
        if (id == null ||
            recipient == null ||
            _readZats(draft['amount_zat']) == null ||
            !_hasQuote(draft)) {
          throw const FormatException();
        }
        if (current()) _openConfirmation(payment, action, draft);
      }
    } catch (_) {
      if (current()) {
        setState(() {
          _errorAttempt = attempt;
          _error = switch (action) {
            'send' => 'Could not confirm that the transaction was sent. Refresh History to check its status.',
            'discard' => 'Could not confirm that the payment was discarded. Refresh History to check its status.',
            _ => 'Could not complete the replacement request. Check History for a replacement draft before trying again.',
          };
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          if (confirmed != null && current()) _confirmation = null;
        });
      }
      if (current()) widget.refresh();
    }
    if (replacement != null && current()) widget.review(replacement);
  }

  Widget _confirmAction(
    Json payment,
    String action,
    Json? draft,
    Json? latest,
  ) {
    final again = payment['phase'] == 'broadcast';
    final (title, actionLabel, cancelLabel, explanation) = switch (action) {
      'send' when again => (
        'Send the same transaction again',
        'Send again',
        'Cancel',
        'Resubmit the same signed transaction to testnet. This does not create a new payment.',
      ),
      'send' => (
        'Send signed payment',
        'Send now',
        'Cancel',
        'Review the signed payment before broadcasting it to testnet.',
      ),
      'discard' => (
        payment['phase'] == 'failed'
            ? 'Discard failed payment'
            : 'Discard payment request',
        'Discard',
        'Keep payment',
        'Close this payment request without sending it.',
      ),
      'cancel' => (
        'Request cancellation',
        'Request approvals',
        'Discard draft',
        'Propose spending the same notes back to the vault, less the network fee. Your vault’s approval policy still applies.',
      ),
      _ => (
        'Retry payment',
        'Request approvals',
        'Discard draft',
        'Propose paying the same recipient again using the same notes. Your vault’s approval policy still applies.',
      ),
    };
    final vault = widget.vault!;
    final attempt = _text(payment['attempt'])!;
    final canContinue =
        latest != null &&
        switch (action) {
          // The draft remains actionable if the original merely expires.
          'retry' ||
          'cancel' => !{
            'confirmed',
            'replaced',
            'spent_unverified',
          }.contains(latest['phase']),
          'send' =>
            !_settled(latest['phase']) &&
                latest['can_send'] == true &&
                latest['sending'] != true &&
                latest['phase'] == payment['phase'] &&
                latest['txid'] == payment['txid'],
          _ => !_settled(latest['phase']) && latest['can_discard'] == true,
        };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 14,
      children: [
        KeyedSubtree(
          key: _reviewHeading,
          child: LokiHead('History', title, explanation),
        ),
        if (draft != null)
          const _ReviewNotice(
            'The original payment may confirm first',
            'Both transactions spend the same notes, so only one can be mined. Requesting approvals does not stop the original payment.',
            warning: true,
          ),
        _PaymentDetails(
          draft == null ? 'Payment details' : 'Replacement quote',
          draft ?? payment,
          vault,
        ),
        if (action == 'send') ...[
          Surface(
            child: ExpansionTile(
              title: const Text('Transaction reference'),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
              children: [
                if (_id(payment['txid']) case final txid?)
                  _identifier(attempt, 'Transaction ID', txid, copy: false),
                _identifier(attempt, 'Payment attempt', attempt, copy: false),
              ],
            ),
          ),
          const _ReviewNotice(
            'Broadcast is not confirmation',
            'The signer checks the payment against blocks reported by its lightwalletd provider.',
          ),
        ] else if (draft != null)
          Surface(
            padding: const EdgeInsets.all(15),
            child: Column(
              spacing: 10,
              children: [
                _identifier(
                  attempt,
                  'Original attempt ID',
                  attempt,
                  copy: false,
                ),
                _identifier(
                  attempt,
                  'New attempt ID',
                  _text(draft['attempt'])!,
                  copy: false,
                ),
              ],
            ),
          )
        else
          const _ReviewNotice(
            'Releases the reserved notes',
            'Discarding releases this payment’s reservation on the input. Nothing is sent.',
            warning: true,
          ),
        if (!canContinue && !_busy)
          const _PaymentNote(
            'This payment’s status changed. Return to History to check available actions.',
            error: true,
          ),
        if (_busy) const LinearProgressIndicator(minHeight: 2),
        const Divider(),
        Wrap(
          alignment: WrapAlignment.end,
          spacing: 8,
          runSpacing: 8,
          children: [
            ActionChipButton(
              cancelLabel,
              Icons.close,
              _busy
                  ? null
                  : draft == null
                  ? () => setState(() => _confirmation = null)
                  : () => _action(
                      payment,
                      action,
                      confirmed: false,
                      draft: draft,
                    ),
            ),
            ActionChipButton(
              actionLabel,
              action == 'discard' ? Icons.delete_outline : Icons.arrow_forward,
              _busy || !canContinue
                  ? null
                  : () =>
                        _action(payment, action, confirmed: true, draft: draft),
              primary: true,
            ),
          ],
        ),
      ],
    );
  }

  Future<void> _identifierAction(
    String attempt,
    String name,
    String value, {
    bool open = false,
  }) async {
    final vault = widget.vault?['vault'];
    try {
      if (open) {
        await widget.explorer(value);
      } else {
        await Clipboard.setData(ClipboardData(text: value));
        if (mounted &&
            widget.vault?['vault'] == vault &&
            widget.selected == attempt) {
          setState(() => _copied = name);
        }
      }
    } catch (_) {
      if (mounted &&
          widget.vault?['vault'] == vault &&
          widget.selected == attempt) {
        setState(() {
          _errorAttempt = attempt;
          _error = open
              ? 'Could not open ZecBlock.'
              : 'Could not copy ${name.toLowerCase()}.';
        });
      }
    }
  }

  Widget _identifier(
    String attempt,
    String name,
    String value, {
    bool copy = true,
  }) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Row(
        children: [
          Expanded(child: LokiLabel(name, color: context.colors.muted)),
          if (copy)
            IconButton(
              tooltip: _copied == name
                  ? 'Copied ${name.toLowerCase()}'
                  : 'Copy ${name.toLowerCase()}',
              onPressed: () => _identifierAction(attempt, name, value),
              icon: Icon(
                _copied == name ? Icons.check : Icons.copy_outlined,
                size: 14,
                color: _copied == name
                    ? context.colors.mint
                    : context.colors.muted,
              ),
              constraints: const BoxConstraints.tightFor(width: 30, height: 27),
              padding: EdgeInsets.zero,
            ),
        ],
      ),
      SelectableText(
        value,
        style: lokiMono(11, color: context.colors.ink).copyWith(height: 1.3),
      ),
    ],
  );

  Widget _inspector(Json payment) {
    final vault = widget.vault!, attempt = _text(payment['attempt'])!;
    final phase = payment['phase'],
        confirmed = phase == 'confirmed',
        settled = _settled(phase);
    final recipient = _text(payment['recipient']), txid = _id(payment['txid']);
    final fee = _readZats(payment['fee_zat']),
        policy = _policy(vault),
        height = payment['mined_height'];
    final replaces = _object(payment['replaces']),
        replacedBy = _id(payment['replaced_by']);
    final hasError = _text(payment['error']) != null;
    final failure = hasError ? paymentFailure(payment) : null;
    final signers = payment['signers'], slot = vault['my_slot'];
    final canReview =
        phase == 'signing' &&
        payment['approval_requested'] != true &&
        !hasError &&
        (slot is! int ||
            signers is! List ||
            signers.isEmpty ||
            signers.contains(slot));
    final canSend =
        !settled && payment['can_send'] == true && payment['sending'] != true;
    final canDiscard = !settled && payment['can_discard'] == true;
    final canReplace = !settled && payment['can_replace'] == true;
    final showTxid =
        txid != null &&
        (confirmed || phase == 'signed' || phase == 'broadcast');
    return Surface(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 8,
        children: [
          Row(
            children: [
              const Expanded(child: LokiLabel('Transaction details')),
              IconButton(
                tooltip: 'Close details',
                onPressed: _busy ? null : () => widget.select(null),
                icon: Icon(Icons.close, size: 15, color: context.colors.muted),
                visualDensity: VisualDensity.compact,
              ),
            ],
          ),
          _AmountHeading(payment['amount_zat'], size: 28, pending: !confirmed),
          Align(alignment: Alignment.centerLeft, child: _phasePill(payment)),
          const Divider(height: 1),
          if (fee != null)
            ValueRow('Network fee', _withUnit(fee.toString()), mono: true),
          if (_utc(payment['created_at']) case final created?)
            ValueRow('Created', created, mono: true),
          if (confirmed && height is int && height > 0)
            ValueRow(
              'Block height',
              MaterialLocalizations.of(context).formatDecimal(height),
              mono: true,
            ),
          if (!confirmed && policy != null)
            ValueRow('Vault policy', '$policy approvals'),
          if (confirmed)
            const _PaymentNote(
              'Confirmed using data reported by lightwalletd.',
            ),
          if (phase == 'broadcast')
            const _PaymentNote(
              'Broadcast to the network. The signer has not matched it to a reported block yet.',
            ),
          if (phase == 'spent_unverified')
            const _PaymentNote(
              'Lightwalletd reported the input as spent. The signer could not verify the spending transaction.',
            ),
          if (phase == 'replaced')
            _PaymentNote(
              'Another transaction spent this payment’s note in a mined block${replacedBy == null ? '' : ' (${_short(replacedBy)})'}. This payment can no longer be mined.',
            ),
          if (replaces != null)
            _PaymentNote(
              '${replaces['cancel'] == true ? 'Cancellation' : 'Retry'} of payment ${_short(_text(replaces['attempt']) ?? 'request')}. Both spend the same notes.',
            ),
          if (!settled && payment['approvals'] is List)
            _ApprovalStatus(vault, payment),
          if (!settled && failure != null)
            _PaymentNote(failure, error: true),
          if (recipient != null) ...[
            const Divider(height: 1),
            _identifier(attempt, 'Recipient', recipient),
          ],
          if (showTxid) ...[
            const Divider(height: 1),
            _identifier(attempt, 'Transaction ID', txid, copy: confirmed),
            if (confirmed)
              ActionChipButton(
                'View on ZecBlock',
                Icons.open_in_new,
                () => _identifierAction(
                  attempt,
                  'Transaction ID',
                  txid,
                  open: true,
                ),
              ),
          ],
          if (canReview || canSend || canDiscard || canReplace) ...[
            const Divider(height: 1),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (canReview)
                  ActionChipButton(
                    'Review proposal',
                    Icons.arrow_forward,
                    _busy ? null : () => widget.review(attempt),
                    primary: true,
                  ),
                if (canSend)
                  ActionChipButton(
                    phase == 'broadcast' ? 'Send again' : 'Send now',
                    Icons.send_outlined,
                    _busy ? null : () => _action(payment, 'send'),
                    primary: true,
                  ),
                if (canDiscard)
                  ActionChipButton(
                    phase == 'signing' ? 'Cancel request' : 'Discard payment',
                    Icons.close,
                    _busy ? null : () => _action(payment, 'discard'),
                  ),
                if (canReplace) ...[
                  ActionChipButton(
                    'Retry payment',
                    Icons.replay,
                    _busy ? null : () => _action(payment, 'retry'),
                  ),
                  ActionChipButton(
                    'Request cancellation',
                    Icons.undo,
                    _busy ? null : () => _action(payment, 'cancel'),
                  ),
                ],
              ],
            ),
          ],
          if (_busy) const LinearProgressIndicator(),
          if (_errorAttempt == attempt && _error != null)
            _PaymentNote(_error!, error: true),
        ],
      ),
    );
  }

  Widget _row(Json payment, {required bool compact, required bool selected}) {
    final colors = context.colors;
    final confirmed = payment['phase'] == 'confirmed';
    final replaces = _object(payment['replaces']);
    final title = payment['direction'] == 'received'
        ? 'Received'
        : payment['amount_is_net'] == true
        ? 'Net outflow'
        // Once mined, a retry is simply a sent payment; its details still name what it replaced.
        : confirmed
        ? (replaces?['cancel'] == true ? 'Cancelled payment' : 'Sent')
        : replaces != null
        ? (replaces['cancel'] == true
              ? 'Cancellation request'
              : 'Retry request')
        : 'Payment proposal';
    final recipient = _text(payment['recipient']);
    final status = paymentPhase(payment);
    final attempt = _text(payment['attempt'])!;
    return Semantics(
      button: true,
      selected: selected,
      child: Ink(
        color: selected
            ? colors.mint.withValues(alpha: colors.dark ? .13 : .11)
            : null,
        child: InkWell(
          onTap: _busy ? null : () => widget.select(attempt),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            child: Row(
              spacing: 10,
              children: [
                CircleAvatar(
                  radius: 15.5,
                  backgroundColor: selected
                      ? colors.mint.withValues(alpha: .09)
                      : colors.secondary,
                  child: Icon(
                    confirmed ? Icons.north_east : Icons.draw_outlined,
                    size: 15,
                    color: selected
                        ? colors.mint
                        : confirmed
                        ? colors.muted
                        : colors.gold,
                  ),
                ),
                Expanded(
                  flex: 3,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    spacing: 4,
                    children: [
                      Text(
                        title,
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (recipient != null)
                        Text(
                          _short(recipient),
                          overflow: TextOverflow.ellipsis,
                          maxLines: 1,
                          style: lokiMono(10, color: colors.muted),
                        ),
                    ],
                  ),
                ),
                if (!compact)
                  Flexible(
                    flex: 2,
                    fit: FlexFit.tight,
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: _phasePill(payment),
                    ),
                  ),
                Expanded(
                  flex: compact ? 3 : 2,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    spacing: 4,
                    children: [
                      Text(
                        _withUnit(payment['amount_zat']),
                        textAlign: TextAlign.right,
                        style: lokiMono(
                          12,
                          bold: true,
                          color: confirmed ? colors.ink : colors.gold,
                        ),
                      ),
                      if (compact)
                        Text(
                          status,
                          textAlign: TextAlign.right,
                          style: TextStyle(
                            fontSize: 10,
                            color: confirmed ? colors.mint : colors.gold,
                          ),
                        ),
                    ],
                  ),
                ),
                Icon(
                  Icons.chevron_right,
                  size: 14,
                  color: selected ? colors.mint : colors.muted,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final vault = widget.vault;
    final records = vault == null
        ? <Json>[]
        : widget.payments.where((p) => _text(p['attempt']) != null).toList();
    final selected = records
        .where((p) => p['attempt'] == widget.selected)
        .firstOrNull;
    if (_confirmation case (:final payment, :final action, :final draft)) {
      return _confirmAction(payment, action, draft, selected);
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 24,
      children: [
        LokiHead(
          vault == null ? 'Workspace' : _vaultName(vault),
          'History',
          'Outgoing payments and proposals from this vault.',
        ),
        LayoutBuilder(
          builder: (context, bounds) {
            final sideBySide = selected != null && bounds.maxWidth >= 610;
            final compact = sideBySide || bounds.maxWidth < 450;
            final inspector = selected == null ? null : _inspector(selected);
            final list = Surface(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(left: 15, right: 8),
                    child: Row(
                      children: [
                        Expanded(
                          child: LokiLabel(
                            'Transactions',
                            color: context.colors.muted,
                          ),
                        ),
                        _PaymentNote(
                          '${records.length} ${records.length == 1 ? 'record' : 'records'}',
                        ),
                        if (vault != null)
                          IconButton(
                            tooltip: 'Refresh history',
                            icon: Icon(
                              Icons.refresh,
                              size: 15,
                              color: context.colors.muted,
                            ),
                            onPressed: _busy ? null : widget.refresh,
                            visualDensity: VisualDensity.compact,
                          ),
                      ],
                    ),
                  ),
                  const Divider(height: 1),
                  if (records.isEmpty)
                    Padding(
                      padding: const EdgeInsets.all(18),
                      child: _PaymentNote(
                        vault == null
                            ? 'Select a vault to view its payments.'
                            : 'No payments yet.',
                      ),
                    ),
                  for (final (index, payment) in records.indexed) ...[
                    if (index > 0)
                      const Divider(height: 1, indent: 14, endIndent: 14),
                    _row(
                      payment,
                      compact: compact,
                      selected: identical(payment, selected),
                    ),
                    if (!sideBySide &&
                        inspector != null &&
                        identical(payment, selected))
                      Padding(
                        padding: const EdgeInsets.all(10),
                        child: inspector,
                      ),
                  ],
                ],
              ),
            );
            if (sideBySide && inspector != null) {
              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                spacing: 12,
                children: [
                  Expanded(child: list),
                  SizedBox(width: 302, child: inspector),
                ],
              );
            }
            return list;
          },
        ),
      ],
    );
  }
}

class _ApprovalStatus extends StatelessWidget {
  const _ApprovalStatus(this.vault, this.status);
  final Json vault, status;

  @override
  Widget build(BuildContext context) {
    final approvals = status['approvals'];
    if (status['signatures_received'] == true) {
      return const _PaymentNote('The signer has the signed transaction data.');
    }
    if (approvals is! List ||
        !const {
          'signing',
          'approved',
          'not_selected',
        }.contains(status['phase'])) {
      return const SizedBox.shrink();
    }
    final signers = (_object(status['intent']) ?? status)['signers'];
    final approved = approvals.whereType<int>().toSet();
    final group = signers is List ? signers.whereType<int>().toSet() : <int>{};
    final count = group.isEmpty
        ? approved.length
        : approved.intersection(group).length;
    final threshold = vault['threshold'];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 7,
      children: [
        _PaymentNote(
          '${threshold is int ? '$count of $threshold' : '$count'} approvals recorded here${group.isEmpty && status['phase'] == 'signing' ? ' · any member can approve' : ''}.',
        ),
        if (group.isNotEmpty || approved.isNotEmpty)
          Wrap(
            spacing: 5,
            runSpacing: 5,
            children: [
              for (final slot in group.isEmpty ? approved : group)
                StatusPill(
                  'Member $slot · ${approved.contains(slot) ? 'approved' : 'waiting'}',
                  pending: !approved.contains(slot),
                ),
            ],
          ),
      ],
    );
  }
}

class PaymentReview extends StatefulWidget {
  const PaymentReview({
    super.key,
    required this.vault,
    required this.attempt,
    required this.request,
    required this.close,
  });
  final Json vault;
  final String attempt;
  final Request request;
  final VoidCallback close;

  @override
  State<PaymentReview> createState() => _PaymentReviewState();
}

class _PaymentReviewState extends State<PaymentReview> {
  Json? _review, _status;
  Timer? _timer;
  bool _loading = false,
      _checking = false,
      _approving = false,
      _requested = false;
  bool _reviewUnavailable = false,
      _statusUnavailable = false,
      _approvalUnknown = false;

  String? get _vaultId => _text(widget.vault['vault']);
  Json get _body => {'vault': _vaultId, 'attempt': widget.attempt};
  bool get _alreadyRequested =>
      _requested || _status?['approval_requested'] == true;

  @override
  void initState() {
    super.initState();
    unawaited(_loadReview());
    unawaited(_loadStatus());
    _timer = Timer.periodic(
      const Duration(seconds: 3),
      (_) => unawaited(_loadStatus()),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _loadReview() async {
    if (_loading || _approving || _alreadyRequested) return;
    setState(() {
      _loading = true;
      _reviewUnavailable = false;
      _approvalUnknown = false;
    });
    try {
      if (_vaultId == null) throw const FormatException();
      final review = await widget.request('payment-review', _body);
      if (_text(review['review_token']) == null ||
          _text(review['intent_hash']) == null ||
          _text(review['recipient']) == null ||
          (_readZats(review['amount_zat']) ?? BigInt.zero) <= BigInt.zero ||
          !_hasQuote(review)) {
        throw const FormatException();
      }
      if (mounted) setState(() => _review = review);
    } catch (_) {
      if (mounted) {
        setState(() {
          _reviewUnavailable = true;
          _review = null;
        });
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadStatus() async {
    if (_checking || _approving) return;
    _checking = true;
    try {
      final vault = _vaultId;
      if (vault == null) throw const FormatException();
      final query = Uri(
        queryParameters: {'vault': vault, 'attempt': widget.attempt},
      ).query;
      final status = await widget.request('payment-status?$query');
      if (_text(status['phase']) == null) throw const FormatException();
      if (mounted) {
        setState(() {
          _status = status;
          _statusUnavailable = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _statusUnavailable = true);
    } finally {
      _checking = false;
    }
  }

  bool get _canContinue =>
      !_approving &&
      !_statusUnavailable &&
      !_alreadyRequested &&
      _review != null &&
      _status?['phase'] == 'signing' &&
      _status?['error'] == null;

  Future<void> _approve() async {
    if (!_canContinue) return;
    final review = _review!;
    setState(() {
      _approving = true;
      _approvalUnknown = false;
    });
    try {
      await widget.request('payment-approve', {
        ..._body,
        'review_token': review['review_token'],
        'intent_hash': review['intent_hash'],
      });
      if (mounted) setState(() => _requested = true);
    } catch (_) {
      if (mounted) {
        setState(() {
          _approvalUnknown = true;
          _review = null;
        });
      }
    } finally {
      if (mounted) {
        setState(() => _approving = false);
        unawaited(_loadStatus());
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final colors = context.colors, status = _status, review = _review;
    final replaces = _object(review?['replaces']);
    final noLongerOpen =
        status != null &&
        (status['phase'] != 'signing' || status['error'] != null);
    final showingPreview =
        !_alreadyRequested && !noLongerOpen && review != null;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 10,
      children: [
        LokiHead(
          'Proposal preview',
          _alreadyRequested ? 'Approval requested' : 'Review proposal',
          _alreadyRequested
              ? 'Follow the signer’s progress here or in History.'
              : 'Check the proposed recipient, amount, and fee before continuing to signer review.',
        ),
        if (replaces != null)
          Surface(
            color: colors.gold.withValues(alpha: .08),
            radius: 12,
            padding: const EdgeInsets.all(13),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              spacing: 6,
              children: [
                LokiLabel(
                  replaces['cancel'] == true
                      ? 'Cancels a stuck payment'
                      : 'Retries a stuck payment',
                  color: colors.gold,
                ),
                _PaymentNote(
                  'Replaces ${_short(_text(replaces['attempt']) ?? 'an earlier payment')}. Both proposals spend the same notes, so at most one can be mined.',
                ),
                if (_readZats(replaces['amount_zat']) != null)
                  ValueRow(
                    'Original amount',
                    _withUnit(replaces['amount_zat']),
                    mono: true,
                  ),
                if (_text(replaces['recipient']) case final original?)
                  SelectableText(original, style: lokiMono(10)),
              ],
            ),
          ),
        if (review != null)
          _PaymentDetails('Proposed payment', review, widget.vault),
        if (showingPreview)
          const _ReviewNotice(
            'Not yet signed',
            'Continuing opens the local signer. Touch ID unlocks the key; it does not approve this payment.',
          ),
        if (status != null && !showingPreview) ...[
          Align(alignment: Alignment.centerLeft, child: _phasePill(status)),
          _ApprovalStatus(widget.vault, status),
        ],
        if (_loading || _approving) const LinearProgressIndicator(),
        if (_statusUnavailable)
          const _PaymentNote(
            'Could not refresh payment status. The app will keep checking.',
            error: true,
          ),
        if (status?['error'] != null)
          _PaymentNote(
            '${paymentFailure(status) ?? 'The signer reported a problem.'} Check History for available actions.',
            error: true,
          ),
        if (_approvalUnknown && !_alreadyRequested && !noLongerOpen)
          const _PaymentNote(
            'Could not confirm the approval request. Check the current status before trying again.',
            error: true,
          ),
        if (_reviewUnavailable && !_alreadyRequested && !noLongerOpen)
          const _PaymentNote(
            'This proposal is not available to review yet or cannot be approved on this device.',
            error: true,
          ),
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          minTileHeight: 34,
          title: Text(
            showingPreview
                ? 'Approval status and identifiers'
                : 'Transaction identifiers',
            style: TextStyle(fontSize: 12, color: colors.muted),
          ),
          children: [
            if (status != null && showingPreview) ...[
              _phasePill(status),
              _ApprovalStatus(widget.vault, status),
              const SizedBox(height: 8),
            ],
            const LokiLabel('Payment attempt'),
            SelectableText(widget.attempt, style: lokiMono(11)),
          ],
        ),
        const Divider(height: 1),
        Wrap(
          alignment: WrapAlignment.end,
          spacing: 8,
          runSpacing: 8,
          children: [
            ActionChipButton(
              'Back',
              Icons.arrow_back,
              _approving ? null : widget.close,
            ),
            if (!_alreadyRequested &&
                !noLongerOpen &&
                review == null &&
                !_loading &&
                !_approving)
              ActionChipButton(
                'Reload proposal',
                Icons.refresh,
                _approvalUnknown && (_checking || _statusUnavailable)
                    ? null
                    : _loadReview,
              ),
            if (!_alreadyRequested && !noLongerOpen && review != null)
              ActionChipButton(
                _approving ? 'Opening signer…' : 'Continue to signer',
                Icons.arrow_forward,
                _canContinue ? _approve : null,
                primary: true,
              ),
          ],
        ),
      ],
    );
  }
}
