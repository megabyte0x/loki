import 'package:loki_signer/wallet_api.dart';

// UI-only signer double. Not imported by the product entry point.
class FixtureWallet implements WalletApi {
  FixtureWallet({this.running = true, this.fresh = false});
  static const recipient =
      'utest1ae4vks28mx9wa6c5k73qhndp4xguktz9fr8spc0m3y7j6adn2qwv5r8ce03p6wnjmq8s9ey2x75fdv0stdwjk4l7f3sgvszv6n59c0t8rxgk24yj';
  static final studio = '7d193b42${'b' * 50}a3cd98';
  static final reserve = 'b352a17e${'c' * 50}d8056e';
  static final proposal = 'a' * 64;
  static final sent = 'b' * 64;
  static const txid =
      '8c7e5a103fc2b664a09ed4cbca4b9f51117fd1a59eedbe257f51bd80791a532e';

  bool running,
      confirmed = true,
      inviting = false,
      broadcast = true,
      failed = false;
  final bool fresh;
  String coordinator = 'https://coordinator.example';
  String? openedTx, pairLink, invite;
  final writes = <(String, Json)>[];

  Json get pending => {
    'attempt': proposal,
    'amount_zat': '40000000',
    'recipient': recipient,
    'proposer': 2,
    'phase': failed ? 'failed' : 'signing',
    'can_discard': true,
  };

  @override
  Future<Json> profile() async => {
    'profile': fresh && !running ? 'fresh' : 'vault',
    'running': running,
    'slot': 1,
  };

  @override
  Future<Json> request(String path, [Json? body]) async {
    if (!running) throw StateError('locked');
    if (body != null) writes.add((path, body));
    final uri = Uri.parse(path);
    return switch (uri.path) {
      'status' when uri.hasQuery && inviting => {
        'phase': 'waiting_members',
        'invites': [
          {'slot': 2, 'code': 'test-invite'},
        ],
      },
      'status' when uri.hasQuery => {
        'phase': 'compare_roster',
        'fingerprint': 'd' * 64,
        'roster_code': '5824 7906 1348 0527 6193 8072',
        'confirmations': 0,
        'confirmed': false,
      },
      'status' => {
        'phase': 'home',
        'network': 'testnet',
        'paired_coordinator': coordinator,
        'vaults': [
          {
            'vault': studio,
            'name': 'Studio vault',
            'active': true,
            'threshold': 2,
            'members': 3,
            'my_slot': 1,
          },
          {
            'vault': reserve,
            'name': 'Reserve vault',
            'active': false,
            'threshold': 2,
            'members': 3,
            'my_slot': 1,
          },
        ],
      },
      'pending' => {
        'pending': [if (!failed) pending],
      },
      'balance' => {'balance_zat': 1248000000},
      'payments' => {
        'payments': [
          pending,
          {
            'attempt': sent,
            'direction': 'sent',
            'amount_zat': '12000000',
            'fee_zat': '10000',
            'txid': txid,
            'phase': confirmed
                ? 'confirmed'
                : broadcast
                ? 'broadcast'
                : 'signed',
            'mined_height': confirmed ? 3660192 : null,
            'recipient': recipient,
            'can_send': !confirmed,
            'can_replace': !confirmed && broadcast,
          },
          {
            'attempt': 'c' * 64,
            'direction': 'sent',
            'amount_zat': '125000000',
            'fee_zat': '10000',
            'txid': 'e' * 64,
            'phase': 'confirmed',
            'mined_height': 3659008,
            'recipient': '${recipient.substring(0, recipient.length - 4)}my6h',
          },
        ],
      },
      'payment-draft' => {
        'attempt': 'd' * 64,
        'fee_zat': '10000',
        'change_zat': '59990000',
      },
      'create' || 'join' => {'vault': reserve},
      'payment-replace' => {
        'attempt': 'e' * 64,
        'recipient': recipient,
        'amount_zat': '12000000',
        'fee_zat': '10000',
        'change_zat': '59990000',
      },
      'payment-discard' ||
      'payment-send' ||
      'payment-publish' ||
      'payment-verify' ||
      'payment-approve' ||
      'agree' => <String, dynamic>{},
      'payment-review' => {
        'review_token': 'f' * 64,
        'intent_hash': 'c' * 64,
        'recipient': recipient,
        'amount_zat': '40000000',
        'fee_zat': '10000',
        'change_zat': '59990000',
        'memo': 'Studio expenses',
      },
      'payment-status' => {
        'phase': 'signing',
        'approvals': [],
        'intent': {'proposer': 2, 'signers': []},
      },
      'recovery-status' => {'recovery_backup': true},
      _ => throw UnsupportedError(path),
    };
  }

  @override
  Future<void> unlock() async => running = true;
  @override
  Future<void> pair(String link) async {
    pairLink = link;
    running = true;
  }

  @override
  Future<String?> pendingInvite() async {
    if (!running) return null;
    final code = invite;
    invite = null;
    return code;
  }

  @override
  Future<void> restore() async {}
  @override
  Future<void> lock() async => running = false;
  @override
  Future<List<Json>> addresses() async => [
    {'name': 'Studio vault', 'slot': 1, 'address': recipient},
  ];
  @override
  Future<void> exportBackup(String vault) async {}
  @override
  Future<void> explorer(String txid) async => openedTx = txid;
  @override
  Future<void> appearance(String mode) async {}
}
