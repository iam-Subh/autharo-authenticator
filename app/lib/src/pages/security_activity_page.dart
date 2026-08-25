import 'dart:convert';

import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/security_elevation.dart';

class SecurityActivityPage extends StatefulWidget {
  const SecurityActivityPage({super.key});

  @override
  State<SecurityActivityPage> createState() => _SecurityActivityPageState();
}

class _SecurityActivityPageState extends State<SecurityActivityPage> {
  List<rust.SecurityEventView>? _events;
  Object? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _authorizeAndLoad());
  }

  Future<void> _authorizeAndLoad() async {
    try {
      final authorized = await authorizeScope(
        context,
        scope: securityReadScope,
        action: AppLocalizations.of(context).securityActivity,
      );
      if (authorized && mounted) await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _load() async {
    setState(() => _error = null);
    try {
      final events = await rust.listSecurityActivity();
      if (mounted) setState(() => _events = events);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.securityActivity),
        actions: [
          IconButton(
            onPressed: _authorizeAndLoad,
            icon: const Icon(Icons.refresh),
            tooltip: l10n.refresh,
          ),
        ],
      ),
      body: RefreshIndicator(onRefresh: _load, child: _content()),
    );
  }

  Widget _content() {
    final l10n = AppLocalizations.of(context);
    if (_error != null) {
      return ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text('${_error!}'),
          const SizedBox(height: 16),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton.tonal(
              onPressed: _authorizeAndLoad,
              child: Text(l10n.tryAgain),
            ),
          ),
        ],
      );
    }
    final events = _events;
    if (events == null) return const Center(child: CircularProgressIndicator());
    if (events.isEmpty) {
      return ListView(
        padding: const EdgeInsets.all(24),
        children: [Text(l10n.noSecurityActivity)],
      );
    }
    return ListView.separated(
      itemCount: events.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (context, index) => _EventTile(event: events[index]),
    );
  }
}

class _EventTile extends StatelessWidget {
  const _EventTile({required this.event});

  final rust.SecurityEventView event;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final detail = _detail();
    return ListTile(
      leading: Icon(_icon),
      title: Text(_title(l10n)),
      subtitle: Text(
        [?event.deviceName, _time(event.createdAt), ?detail].join(' • '),
      ),
    );
  }

  IconData get _icon => switch (event.eventType) {
    'device_added' => Icons.add_to_home_screen_outlined,
    'account_registered' => Icons.person_add_alt_1_outlined,
    'device_revoked' => Icons.phonelink_erase_outlined,
    'device_approval_created' => Icons.phonelink_lock_outlined,
    'signed_out' || 'signed_out_everywhere' => Icons.logout,
    'refresh_replay_detected' => Icons.warning_amber_outlined,
    'recovery_access_enrolled' => Icons.key_outlined,
    _ => Icons.security_outlined,
  };

  String _title(AppLocalizations l10n) => switch (event.eventType) {
    'device_added' => l10n.securityDeviceAdded,
    'account_registered' => l10n.securityAccountRegistered,
    'device_revoked' => l10n.securityDeviceRemoved,
    'device_approval_created' => l10n.securityApprovalCreated,
    'signed_out' => l10n.securityDeviceSignedOut,
    'signed_out_everywhere' => l10n.securityAllDevicesSignedOut,
    'refresh_replay_detected' => l10n.securityTokenReuseDetected,
    'recovery_access_enrolled' => l10n.securityRecoveryEnabled,
    _ => event.eventType.replaceAll('_', ' '),
  };

  String? _detail() {
    try {
      final value = jsonDecode(event.detailJson);
      if (value is! Map<String, dynamic>) return null;
      final platform = value['platform'];
      return platform is String ? platform : null;
    } catch (_) {
      return null;
    }
  }

  static String _time(String raw) {
    final parsed = DateTime.tryParse(raw);
    if (parsed == null) return raw;
    final value = parsed.toLocal();
    return '${value.year}-${value.month.toString().padLeft(2, '0')}-'
        '${value.day.toString().padLeft(2, '0')} '
        '${value.hour.toString().padLeft(2, '0')}:'
        '${value.minute.toString().padLeft(2, '0')}';
  }
}
