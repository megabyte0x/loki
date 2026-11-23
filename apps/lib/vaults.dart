import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'design.dart';
import 'wallet_api.dart';

const _retiredLink =
    'This kind of invite link is no longer accepted. Ask the vault creator for a new invite.';
const _otherLink =
    'LokiSigner only reads invite links from your paired coordinator. Paste the invite code instead.';

/// The invite code from pasted text, or why LokiSigner refuses it. A bare code passes through.
/// A full link must be exactly `<paired coordinator>/#invite=<code>`, the same rule as a link
/// opened in the app: HTTPS, no credentials, path or query, and no other fragment fields.
({String? code, String? error}) inviteCode(String text, String? coordinator) {
  if (!text.contains(':') && !text.contains('/')) {
    return (code: text, error: null);
  }
  final Uri uri;
  try {
    uri = Uri.parse(text);
  } on FormatException {
    return (code: null, error: null);
  }
  if (uri.hasQuery &&
      uri.query.split('&').any((p) => p.split('=').first == 'invite')) {
    return (code: null, error: _retiredLink);
  }
  final fragment = uri.hasFragment ? uri.fragment : '';
  if (coordinator == null ||
      uri.scheme != 'https' ||
      uri.userInfo.isNotEmpty ||
      'https://${uri.authority}'.toLowerCase() != coordinator.toLowerCase() ||
      uri.hasQuery ||
      (uri.path.isNotEmpty && uri.path != '/') ||
      !fragment.startsWith('invite=')) {
    return (code: null, error: _otherLink);
  }
  try {
    return (code: Uri.decodeComponent(fragment.substring(7)), error: null);
  } on ArgumentError {
    return (code: null, error: null);
  } on FormatException {
    return (code: null, error: null);
  }
}

/// A share link on the pinned wallet origin; the code alone when no HTTPS origin is pinned.
String inviteLink(String? coordinator, String code) {
  final origin = coordinator == null ? null : Uri.tryParse(coordinator);
  if (origin == null ||
      origin.scheme != 'https' ||
      origin.host.isEmpty ||
      origin.hasQuery ||
      origin.hasFragment ||
      (origin.path.isNotEmpty && origin.path != '/')) {
    return code;
  }
  return '${origin.origin}/#invite=$code';
}

String vaultName(Json vault) => vault['name'] as String? ?? 'Vault';
String policy(Json vault) =>
    '${vault['threshold']} of ${vault['members']} approvals';

class Notice extends StatelessWidget {
  const Notice(this.message, {super.key});
  final String message;
  @override
  Widget build(BuildContext context) => Surface(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
    child: Semantics(
      liveRegion: true,
      child: Text(message, style: lokiSans(12, color: context.colors.muted)),
    ),
  );
}

class CopyButton extends StatefulWidget {
  const CopyButton(this.label, this.value, this.success, {super.key});
  final String label, value, success;

  @override
  State<CopyButton> createState() => _CopyButtonState();
}

class _CopyButtonState extends State<CopyButton> {
  String? feedback;

  @override
  void didUpdateWidget(covariant CopyButton oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.value != oldWidget.value) feedback = null;
  }

  Future<void> copy() async {
    final value = widget.value;
    var message = widget.success;
    try {
      await Clipboard.setData(ClipboardData(text: value));
    } catch (_) {
      message = 'Could not copy to the clipboard.';
    }
    if (mounted && widget.value == value) setState(() => feedback = message);
  }

  @override
  Widget build(BuildContext context) => Wrap(
    spacing: 9,
    runSpacing: 6,
    crossAxisAlignment: WrapCrossAlignment.center,
    children: [
      ActionChipButton(widget.label, Icons.copy_outlined, copy),
      if (feedback case final message?)
        Semantics(
          liveRegion: true,
          child: Text(
            message,
            style: lokiSans(11, color: context.colors.muted),
          ),
        ),
    ],
  );
}

class VaultLibrary extends StatelessWidget {
  const VaultLibrary({
    super.key,
    required this.vaults,
    required this.open,
    required this.busy,
    required this.create,
    required this.join,
  });
  final List<Json> vaults;
  final ValueChanged<Json> open;
  final bool busy;
  final VoidCallback create, join;

  @override
  Widget build(BuildContext context) {
    final active = vaults.where((v) => v['active'] == true);
    final setup = vaults.where((v) => v['active'] != true);
    final c = context.colors;
    Widget card(Json v, bool active) {
      final tint = active ? c.mint : c.gold;
      return Surface(
        child: InkWell(
          onTap: () => open(v),
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Row(
              children: [
                Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: tint.withValues(alpha: .10),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    active ? Icons.lock_outline : Icons.pending_outlined,
                    color: tint,
                    size: 22,
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        vaultName(v),
                        style: lokiSans(17, weight: 600, spacing: -.4),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        shortId(v['vault'] as String),
                        style: lokiMono(10, color: c.muted),
                      ),
                    ],
                  ),
                ),
                StatusPill(
                  active ? policy(v) : 'Set up vault',
                  pending: !active,
                ),
                const SizedBox(width: 8),
                Icon(Icons.chevron_right, color: c.muted, size: 16),
              ],
            ),
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            const Expanded(
              child: LokiHead(
                'Workspace',
                'All vaults',
                'Your active vaults and setups in progress on this Mac.',
              ),
            ),
            ActionChipButton('Join vault', Icons.link, busy ? null : join),
            const SizedBox(width: 8),
            ActionChipButton(
              'Create vault',
              Icons.add,
              busy ? null : create,
              primary: true,
            ),
          ],
        ),
        const SizedBox(height: 31),
        const LokiLabel('Active vaults'),
        const SizedBox(height: 10),
        if (active.isEmpty)
          const Notice(
            'No active vaults. Create a vault or join one with an invitation.',
          ),
        for (final v in active) ...[card(v, true), const SizedBox(height: 8)],
        if (setup.isNotEmpty) ...[
          const SizedBox(height: 18),
          const LokiLabel('Setting up'),
          const SizedBox(height: 10),
          for (final v in setup) ...[card(v, false), const SizedBox(height: 8)],
        ],
      ],
    );
  }
}

class VaultForm extends StatefulWidget {
  const VaultForm({
    super.key,
    required this.join,
    required this.busy,
    required this.cancel,
    required this.submit,
    this.initialInvite,
    this.coordinator,
  });
  final bool join, busy;
  final String? initialInvite, coordinator;
  final VoidCallback cancel;
  final ValueChanged<Json> submit;
  @override
  State<VaultForm> createState() => _VaultFormState();
}

class _VaultFormState extends State<VaultForm> {
  final form = GlobalKey<FormState>();
  String name = '';
  int members = 3, threshold = 2;
  ({
    String code,
    String name,
    int slot,
    int members,
    int threshold,
    String? legacyCreator,
  })?
  invite;
  String? inviteError;

  @override
  void initState() {
    super.initState();
    if (widget.initialInvite case final code?) readInvite(code);
  }

  // An invitation preview is unverified; the signer still validates and enrolls it.
  void readInvite(String input) {
    invite = null;
    final (:code, :error) = inviteCode(input.trim(), widget.coordinator);
    inviteError = error;
    if (code == null) return;
    if (!RegExp(r'^[A-Za-z0-9_-]{1,4096}$').hasMatch(code)) return;
    try {
      final fields = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(code))),
      );
      if (fields
          case {
            'vault': final String vault,
            'name': final String name,
            'token': final String token,
            'creator_base_url': final String creator,
            'slot': final int slot,
            'members': final int members,
            'threshold': final int threshold,
          }
          when RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(vault) &&
              name.trim().isNotEmpty &&
              utf8.encode(name).length <= 80 &&
              token.isNotEmpty &&
              members >= 2 &&
              members <= 16 &&
              threshold >= 2 &&
              threshold < members &&
              slot >= 2 &&
              slot <= members) {
        // A relay invite carries the creator's identity; the signer reaches it over its own
        // relay, so the endpoint and relay named in the invite are not destinations.
        final relay = fields['creator'] != null || fields['frostd_url'] != null;
        if (relay && fields['creator'] is! Map) return;
        invite = (
          code: code,
          name: name,
          slot: slot,
          members: members,
          threshold: threshold,
          legacyCreator: relay ? null : creator,
        );
      }
    } on FormatException {
      // Report invalid pasted content through the form, not a decoder error.
    }
  }

  @override
  Widget build(BuildContext context) {
    final joining = widget.join;
    final details = invite;
    Widget count(
      String label,
      int value,
      int min,
      int max,
      ValueChanged<int> change,
    ) => Surface(
      color: context.colors.secondary,
      radius: 10,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Row(
        children: [
          Expanded(child: LokiLabel(label, color: context.colors.muted)),
          IconButton(
            tooltip: 'Fewer $label',
            onPressed: widget.busy || value <= min
                ? null
                : () => change(value - 1),
            icon: const Icon(Icons.remove, size: 16),
          ),
          Text('$value', style: lokiMono(13)),
          IconButton(
            tooltip: 'More $label',
            onPressed: widget.busy || value >= max
                ? null
                : () => change(value + 1),
            icon: const Icon(Icons.add, size: 16),
          ),
        ],
      ),
    );

    return Form(
      key: form,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 14,
        children: [
          LokiHead(
            'Workspace',
            joining ? 'Review vault invite' : 'Create vault',
            joining
                ? 'Paste the invitation from your vault organizer and check its details before joining.'
                : 'Name your vault and choose how many members must approve each payment.',
          ),
          Surface(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              spacing: 12,
              children: [
                LokiLabel(joining ? 'Invitation' : 'Vault details'),
                if (joining)
                  TextFormField(
                    autofocus: true,
                    readOnly: widget.busy,
                    initialValue: widget.initialInvite,
                    obscureText: true,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: 'Invite link or code',
                    ),
                    onChanged: (text) => setState(() => readInvite(text)),
                    validator: (text) => text?.trim().isEmpty != false
                        ? 'Paste an invitation.'
                        : invite == null
                        ? inviteError ?? 'This invite could not be read. Check the link or ask your organizer for a new invite.'
                        : null,
                  )
                else ...[
                  TextFormField(
                    autofocus: true,
                    readOnly: widget.busy,
                    decoration: const InputDecoration(labelText: 'Vault name'),
                    onChanged: (value) => name = value.trim(),
                    validator: (_) =>
                        name.isEmpty || utf8.encode(name).length > 80
                        ? 'Enter a vault name of 1–80 bytes.'
                        : null,
                  ),
                  count(
                    'members',
                    members,
                    3,
                    16,
                    (n) => setState(() {
                      members = n;
                      if (threshold >= members) threshold = members - 1;
                    }),
                  ),
                  count('approvals', threshold, 2, members - 1, (n) {
                    setState(() => threshold = n);
                  }),
                  const Divider(),
                  ValueRow('Vault policy', '$threshold of $members approvals'),
                  const ValueRow('Network', 'Testnet'),
                ],
              ],
            ),
          ),
          if (joining && details != null)
            Surface(
              padding: const EdgeInsets.all(18),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                spacing: 10,
                children: [
                  const LokiLabel('Details from the invite'),
                  ValueRow('Vault name (set by creator)', details.name),
                  ValueRow(
                    'Vault policy',
                    '${details.threshold} of ${details.members} approvals',
                  ),
                  ValueRow('Your member slot', 'Member ${details.slot}'),
                  const ValueRow('Network', 'Testnet'),
                  const Divider(),
                  if (details.legacyCreator case final creator?) ...[
                    LokiLabel(
                      'Creator endpoint in the invite',
                      color: context.colors.muted,
                    ),
                    SelectableText(creator, style: lokiMono(11)),
                    Text(
                      'This older invite joins the creator directly. Its HTTPS origin must be an allowed peer on this Mac.',
                      style: lokiSans(11, color: context.colors.muted),
                    ),
                  ] else ...[
                    const ValueRow('Route', 'This signer’s relay'),
                    Text(
                      'LokiSigner joins through the relay configured for this signer and checks the creator’s identity from the invite. It contacts no address named in the invite.',
                      style: lokiSans(11, color: context.colors.muted),
                    ),
                  ],
                ],
              ),
            ),
          Notice(
            joining
                ? 'Only use an invite from your vault organizer. Joining approves no payment. After you join, compare roster codes with every member over a trusted channel before creating keys.'
                : 'You’ll get a separate invite for each other member. Share them privately and compare roster codes together before creating keys.',
          ),
          if (widget.busy) const LinearProgressIndicator(minHeight: 2),
          const Divider(),
          Wrap(
            alignment: WrapAlignment.end,
            spacing: 8,
            children: [
              ActionChipButton(
                'Cancel',
                Icons.close,
                widget.busy ? null : widget.cancel,
              ),
              ActionChipButton(
                joining ? 'Join vault' : 'Create vault',
                joining ? Icons.link : Icons.add,
                widget.busy
                    ? null
                    : () {
                        if (!form.currentState!.validate()) return;
                        widget.submit(
                          joining
                              ? {'invite': invite!.code}
                              : {
                                  'name': name,
                                  'members': members,
                                  'threshold': threshold,
                                },
                        );
                      },
                primary: true,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class VaultSetup extends StatelessWidget {
  const VaultSetup({
    super.key,
    required this.vault,
    required this.status,
    required this.busy,
    required this.compare,
    required this.startOver,
    this.coordinator,
  });
  final Json vault, status;
  final String? coordinator;
  final bool busy;
  final VoidCallback compare, startOver;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final phase = status['phase'];
    final step = switch (phase) {
      'compare_roster' => 1,
      'creating_keys' => 2,
      'active' => 3,
      _ => 0,
    };
    const steps = ['Members', 'Verify members', 'Create keys', 'Active'];
    final invites = jsonRows(status['invites']);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        LokiHead(vaultName(vault), 'Set up vault'),
        const SizedBox(height: 18),
        Row(
          children: [
            for (var i = 0; i < steps.length; i++) ...[
              if (i != 0)
                const Expanded(
                  child: Padding(
                    padding: EdgeInsets.symmetric(horizontal: 8),
                    child: Divider(),
                  ),
                ),
              Icon(
                i < step
                    ? Icons.check_circle
                    : i == step
                    ? Icons.radio_button_checked
                    : Icons.radio_button_unchecked,
                size: 13,
                color: i <= step ? c.mint : c.muted,
              ),
              const SizedBox(width: 5),
              Text(
                steps[i],
                style: lokiSans(
                  11,
                  weight: i == step ? 600 : 400,
                  color: i == step ? c.ink : c.muted,
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 18),
        if (phase == 'compare_roster')
          roster(context)
        else if (phase == 'creating_keys')
          const Notice(
            'Creating keys on the member devices. Keep LokiSigner open while the ceremony completes.',
          )
        else if (phase == 'setup_interrupted') ...[
          Notice(
            describeError(null, status['error'] as String?) ??
                'Key generation was interrupted. Use a new vault and new invitations.',
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerLeft,
            child: ActionChipButton(
              'Create a new vault',
              Icons.add,
              busy ? null : startOver,
              primary: true,
            ),
          ),
        ] else if (status.isEmpty)
          const Notice('Loading vault setup…')
        else ...[
          Notice(
            invites.isEmpty
                ? 'Waiting for the other members. Leave LokiSigner open to follow setup.'
                : 'Give each member their own invite link over a trusted channel. They can paste it in Join vault.',
          ),
          for (final invite in invites) ...[
            const SizedBox(height: 8),
            Surface(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
              child: Row(
                children: [
                  Text('Member ${invite['slot']}'),
                  const Spacer(),
                  if (invite['joined'] == true)
                    const StatusPill('Joined')
                  else if (invite['code'] case final String code)
                    CopyButton(
                      'Copy invite',
                      inviteLink(coordinator, code),
                      'Invite copied',
                    ),
                ],
              ),
            ),
          ],
        ],
      ],
    );
  }

  Widget roster(BuildContext context) {
    final c = context.colors;
    final code = (status['roster_code'] as String? ?? '').replaceAll(
      RegExp(r'\s'),
      '',
    );
    final groups = RegExp(r'^\d{24}$').hasMatch(code)
        ? RegExp(r'\d{4}').allMatches(code).map((m) => m.group(0)!).toList()
        : <String>[];
    final confirmed = status['confirmed'] == true;
    final refused = status['roster_dialog'] == 'codes_differ';
    final waiting = status['roster_dialog'] == 'open';
    return Surface(
      padding: const EdgeInsets.all(21),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const LokiLabel('Roster verification'),
          const SizedBox(height: 13),
          Text(
            'Do the roster codes match?',
            style: lokiSans(21, weight: 600, spacing: -.65),
          ),
          const SizedBox(height: 12),
          Text(
            'Compare all six groups with every member over a trusted channel, such as a phone call or in person.',
            style: lokiSans(13, color: c.muted),
          ),
          if (groups.isNotEmpty) ...[
            const SizedBox(height: 14),
            Row(
              children: [
                for (var i = 0; i < groups.length; i++) ...[
                  if (i != 0) const SizedBox(width: 6),
                  Expanded(
                    child: Surface(
                      color: c.secondary,
                      radius: 9,
                      padding: const EdgeInsets.symmetric(vertical: 15),
                      child: Text(
                        groups[i],
                        textAlign: TextAlign.center,
                        style: lokiMono(16, bold: true),
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ],
          const SizedBox(height: 14),
          const Divider(),
          const SizedBox(height: 12),
          ValueRow('Vault name (set by creator)', vaultName(vault)),
          const SizedBox(height: 9),
          ValueRow('Policy', policy(vault)),
          if (vault['my_slot'] case final int slot) ...[
            const SizedBox(height: 9),
            ValueRow('Your slot', 'Member $slot'),
          ],
          if (status['confirmations'] case final int count) ...[
            const SizedBox(height: 9),
            ValueRow('Confirmed here', '$count of ${vault['members']}'),
          ],
          const SizedBox(height: 13),
          const Divider(),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: Text(
                  refused
                      ? 'Codes differed. LokiSigner refuses this setup until it restarts.'
                      : confirmed
                      ? 'You confirmed. Waiting for the other members.'
                      : 'Continue to compare the codes in LokiSigner.',
                  style: lokiSans(11, color: c.muted),
                ),
              ),
              if (!confirmed && !refused)
                ActionChipButton(
                  'Compare in LokiSigner',
                  Icons.shield_outlined,
                  busy ||
                          waiting ||
                          groups.isEmpty ||
                          status['fingerprint'] == null
                      ? null
                      : compare,
                  primary: true,
                ),
            ],
          ),
        ],
      ),
    );
  }
}
