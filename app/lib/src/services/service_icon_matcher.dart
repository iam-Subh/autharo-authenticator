import 'package:flutter/material.dart';
import 'package:simple_icons/simple_icons.dart';

/// A bundled service icon selected from an OTP issuer or account domain.
class ServiceIconMatch {
  const ServiceIconMatch({required this.icon, required this.colour});

  final IconData icon;
  final Color colour;
}

class ServiceIconMatcher {
  ServiceIconMatcher._();

  static const _brands = <({List<String> aliases, ServiceIconMatch match})>[
    (
      aliases: ['github'],
      match: ServiceIconMatch(
        icon: SimpleIcons.github,
        colour: Color(0xff181717),
      ),
    ),
    (
      aliases: ['gitlab'],
      match: ServiceIconMatch(
        icon: SimpleIcons.gitlab,
        colour: Color(0xfffc6d26),
      ),
    ),
    (
      aliases: ['gmail', 'google mail', 'googlemail'],
      match: ServiceIconMatch(
        icon: SimpleIcons.gmail,
        colour: Color(0xffea4335),
      ),
    ),
    (
      aliases: ['youtube'],
      match: ServiceIconMatch(
        icon: SimpleIcons.youtube,
        colour: Color(0xffff0000),
      ),
    ),
    (
      aliases: ['google', 'google cloud', 'gcp'],
      match: ServiceIconMatch(
        icon: SimpleIcons.google,
        colour: Color(0xff4285f4),
      ),
    ),
    (
      aliases: ['apple', 'icloud'],
      match: ServiceIconMatch(
        icon: SimpleIcons.apple,
        colour: Color(0xff000000),
      ),
    ),
    (
      aliases: ['discord'],
      match: ServiceIconMatch(
        icon: SimpleIcons.discord,
        colour: Color(0xff5865f2),
      ),
    ),
    (
      aliases: ['steam'],
      match: ServiceIconMatch(
        icon: SimpleIcons.steam,
        colour: Color(0xff171a21),
      ),
    ),
    (
      aliases: ['proton', 'proton mail', 'protonmail'],
      match: ServiceIconMatch(
        icon: SimpleIcons.proton,
        colour: Color(0xff6d4aff),
      ),
    ),
    (
      aliases: ['dropbox'],
      match: ServiceIconMatch(
        icon: SimpleIcons.dropbox,
        colour: Color(0xff0061ff),
      ),
    ),
    (
      aliases: ['cloudflare'],
      match: ServiceIconMatch(
        icon: SimpleIcons.cloudflare,
        colour: Color(0xfff38020),
      ),
    ),
    (
      aliases: ['instagram'],
      match: ServiceIconMatch(
        icon: SimpleIcons.instagram,
        colour: Color(0xffe4405f),
      ),
    ),
    (
      aliases: ['facebook'],
      match: ServiceIconMatch(
        icon: SimpleIcons.facebook,
        colour: Color(0xff0866ff),
      ),
    ),
    (
      aliases: ['meta'],
      match: ServiceIconMatch(
        icon: SimpleIcons.meta,
        colour: Color(0xff0467df),
      ),
    ),
    (
      aliases: ['reddit'],
      match: ServiceIconMatch(
        icon: SimpleIcons.reddit,
        colour: Color(0xffff4500),
      ),
    ),
    (
      aliases: ['twitter', 'x com'],
      match: ServiceIconMatch(icon: SimpleIcons.x, colour: Color(0xff000000)),
    ),
    (
      aliases: ['bitwarden'],
      match: ServiceIconMatch(
        icon: SimpleIcons.bitwarden,
        colour: Color(0xff175ddc),
      ),
    ),
    (
      aliases: ['paypal'],
      match: ServiceIconMatch(
        icon: SimpleIcons.paypal,
        colour: Color(0xff003087),
      ),
    ),
    (
      aliases: ['stripe'],
      match: ServiceIconMatch(
        icon: SimpleIcons.stripe,
        colour: Color(0xff635bff),
      ),
    ),
    (
      aliases: ['coinbase'],
      match: ServiceIconMatch(
        icon: SimpleIcons.coinbase,
        colour: Color(0xff0052ff),
      ),
    ),
    (
      aliases: ['binance'],
      match: ServiceIconMatch(
        icon: SimpleIcons.binance,
        colour: Color(0xfff0b90b),
      ),
    ),
    (
      aliases: ['twitch'],
      match: ServiceIconMatch(
        icon: SimpleIcons.twitch,
        colour: Color(0xff9146ff),
      ),
    ),
    (
      aliases: ['atlassian'],
      match: ServiceIconMatch(
        icon: SimpleIcons.atlassian,
        colour: Color(0xff1868db),
      ),
    ),
    (
      aliases: ['jira'],
      match: ServiceIconMatch(
        icon: SimpleIcons.jira,
        colour: Color(0xff0052cc),
      ),
    ),
    (
      aliases: ['confluence'],
      match: ServiceIconMatch(
        icon: SimpleIcons.confluence,
        colour: Color(0xff172b4d),
      ),
    ),
    (
      aliases: ['notion'],
      match: ServiceIconMatch(
        icon: SimpleIcons.notion,
        colour: Color(0xff000000),
      ),
    ),
    (
      aliases: ['digitalocean'],
      match: ServiceIconMatch(
        icon: SimpleIcons.digitalocean,
        colour: Color(0xff0080ff),
      ),
    ),
    (
      aliases: ['auth0'],
      match: ServiceIconMatch(
        icon: SimpleIcons.auth0,
        colour: Color(0xffeb5424),
      ),
    ),
    (
      aliases: ['okta'],
      match: ServiceIconMatch(
        icon: SimpleIcons.okta,
        colour: Color(0xff007dc1),
      ),
    ),
    (
      aliases: ['zoom'],
      match: ServiceIconMatch(
        icon: SimpleIcons.zoom,
        colour: Color(0xff0b5cff),
      ),
    ),
    (
      aliases: ['shopify'],
      match: ServiceIconMatch(
        icon: SimpleIcons.shopify,
        colour: Color(0xff7ab55c),
      ),
    ),
    (
      aliases: ['epic games', 'epicgames'],
      match: ServiceIconMatch(
        icon: SimpleIcons.epicgames,
        colour: Color(0xff313131),
      ),
    ),
    (
      aliases: ['tiktok'],
      match: ServiceIconMatch(
        icon: SimpleIcons.tiktok,
        colour: Color(0xff000000),
      ),
    ),
    (
      aliases: ['spotify'],
      match: ServiceIconMatch(
        icon: SimpleIcons.spotify,
        colour: Color(0xff1ed760),
      ),
    ),
    (
      aliases: ['telegram'],
      match: ServiceIconMatch(
        icon: SimpleIcons.telegram,
        colour: Color(0xff26a5e4),
      ),
    ),
    (
      aliases: ['whatsapp'],
      match: ServiceIconMatch(
        icon: SimpleIcons.whatsapp,
        colour: Color(0xff25d366),
      ),
    ),
    (
      aliases: ['signal'],
      match: ServiceIconMatch(
        icon: SimpleIcons.signal,
        colour: Color(0xff3a76f0),
      ),
    ),
    (
      aliases: ['mastodon'],
      match: ServiceIconMatch(
        icon: SimpleIcons.mastodon,
        colour: Color(0xff6364ff),
      ),
    ),
    (
      aliases: ['docker'],
      match: ServiceIconMatch(
        icon: SimpleIcons.docker,
        colour: Color(0xff2496ed),
      ),
    ),
    (
      aliases: ['kubernetes', 'k8s'],
      match: ServiceIconMatch(
        icon: SimpleIcons.kubernetes,
        colour: Color(0xff326ce5),
      ),
    ),
    (
      aliases: ['npm', 'npmjs'],
      match: ServiceIconMatch(icon: SimpleIcons.npm, colour: Color(0xffcb3837)),
    ),
    (
      aliases: ['pypi', 'python package index'],
      match: ServiceIconMatch(
        icon: SimpleIcons.pypi,
        colour: Color(0xff3775a9),
      ),
    ),
    (
      aliases: ['jetbrains'],
      match: ServiceIconMatch(
        icon: SimpleIcons.jetbrains,
        colour: Color(0xff000000),
      ),
    ),
    (
      aliases: ['wordpress'],
      match: ServiceIconMatch(
        icon: SimpleIcons.wordpress,
        colour: Color(0xff21759b),
      ),
    ),
    (
      aliases: ['drupal'],
      match: ServiceIconMatch(
        icon: SimpleIcons.drupal,
        colour: Color(0xff0678be),
      ),
    ),
    (
      aliases: ['nextcloud'],
      match: ServiceIconMatch(
        icon: SimpleIcons.nextcloud,
        colour: Color(0xff0082c9),
      ),
    ),
    (
      aliases: ['grafana'],
      match: ServiceIconMatch(
        icon: SimpleIcons.grafana,
        colour: Color(0xfff46800),
      ),
    ),
    (
      aliases: ['sentry'],
      match: ServiceIconMatch(
        icon: SimpleIcons.sentry,
        colour: Color(0xff362d59),
      ),
    ),
    (
      aliases: ['tailscale'],
      match: ServiceIconMatch(
        icon: SimpleIcons.tailscale,
        colour: Color(0xff242424),
      ),
    ),
    (
      aliases: ['wireguard'],
      match: ServiceIconMatch(
        icon: SimpleIcons.wireguard,
        colour: Color(0xff88171a),
      ),
    ),
    (
      aliases: ['figma'],
      match: ServiceIconMatch(
        icon: SimpleIcons.figma,
        colour: Color(0xfff24e1e),
      ),
    ),
    (
      aliases: ['trello'],
      match: ServiceIconMatch(
        icon: SimpleIcons.trello,
        colour: Color(0xff0052cc),
      ),
    ),
    (
      aliases: ['asana'],
      match: ServiceIconMatch(
        icon: SimpleIcons.asana,
        colour: Color(0xfff06a6a),
      ),
    ),
    (
      aliases: ['todoist'],
      match: ServiceIconMatch(
        icon: SimpleIcons.todoist,
        colour: Color(0xffe44332),
      ),
    ),
    (
      aliases: ['vercel'],
      match: ServiceIconMatch(
        icon: SimpleIcons.vercel,
        colour: Color(0xff000000),
      ),
    ),
    (
      aliases: ['netlify'],
      match: ServiceIconMatch(
        icon: SimpleIcons.netlify,
        colour: Color(0xff00c7b7),
      ),
    ),
    (
      aliases: ['firebase'],
      match: ServiceIconMatch(
        icon: SimpleIcons.firebase,
        colour: Color(0xffffca28),
      ),
    ),
    (
      aliases: ['mongodb'],
      match: ServiceIconMatch(
        icon: SimpleIcons.mongodb,
        colour: Color(0xff47a248),
      ),
    ),
    (
      aliases: ['postgres', 'postgresql'],
      match: ServiceIconMatch(
        icon: SimpleIcons.postgresql,
        colour: Color(0xff4169e1),
      ),
    ),
    (
      aliases: ['mysql'],
      match: ServiceIconMatch(
        icon: SimpleIcons.mysql,
        colour: Color(0xff4479a1),
      ),
    ),
    (
      aliases: ['ubuntu'],
      match: ServiceIconMatch(
        icon: SimpleIcons.ubuntu,
        colour: Color(0xffe95420),
      ),
    ),
    (
      aliases: ['linux'],
      match: ServiceIconMatch(
        icon: SimpleIcons.linux,
        colour: Color(0xfffcc624),
      ),
    ),
    (
      aliases: ['ebay'],
      match: ServiceIconMatch(
        icon: SimpleIcons.ebay,
        colour: Color(0xffe53238),
      ),
    ),
    (
      aliases: ['etsy'],
      match: ServiceIconMatch(
        icon: SimpleIcons.etsy,
        colour: Color(0xfff16521),
      ),
    ),
    (
      aliases: ['duolingo'],
      match: ServiceIconMatch(
        icon: SimpleIcons.duolingo,
        colour: Color(0xff58cc02),
      ),
    ),
    (
      aliases: ['coursera'],
      match: ServiceIconMatch(
        icon: SimpleIcons.coursera,
        colour: Color(0xff0056d2),
      ),
    ),
    (
      aliases: ['udemy'],
      match: ServiceIconMatch(
        icon: SimpleIcons.udemy,
        colour: Color(0xffa435f0),
      ),
    ),
    (
      aliases: ['microsoft', 'outlook', 'azure', 'office 365', 'onedrive'],
      match: ServiceIconMatch(icon: Icons.window, colour: Color(0xff00a4ef)),
    ),
    (
      aliases: ['amazon', 'amazon web services', 'aws'],
      match: ServiceIconMatch(icon: Icons.cloud, colour: Color(0xffff9900)),
    ),
    (
      aliases: ['slack'],
      match: ServiceIconMatch(icon: Icons.tag, colour: Color(0xff4a154b)),
    ),
    (
      aliases: ['linkedin'],
      match: ServiceIconMatch(icon: Icons.business, colour: Color(0xff0a66c2)),
    ),
  ];

  static ServiceIconMatch? match({String? issuer, required String account}) {
    return _matchOne(issuer) ?? _matchOne(account);
  }

  static ServiceIconMatch? _matchOne(String? value) {
    final source = _normalize(value ?? '');
    if (source.isEmpty) return null;
    final padded = ' $source ';
    for (final brand in _brands) {
      for (final alias in brand.aliases) {
        final normalizedAlias = _normalize(alias);
        if (padded.contains(' $normalizedAlias ')) return brand.match;
      }
    }
    return null;
  }

  static String _normalize(String value) => value
      .toLowerCase()
      .replaceAll(RegExp('[^a-z0-9]+'), ' ')
      .trim()
      .replaceAll(RegExp(' +'), ' ');
}
