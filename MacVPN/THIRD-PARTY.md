The macOS archive bundles unmodified upstream engine executables (re-signed locally).
Their license texts are included in the application resources.

- Xray-core 26.11.9, MPL-2.0. [Exact upstream release and source](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9).
- sing-box 1.14.4, GPL-3.0-or-later. [Exact upstream release and corresponding source](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4). The upstream release also includes the source download and build configuration.

The built-in routing list combines exact hostnames from the [hxehex mobile internet whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist/blob/fad3653ebd4b212643774a4d10af3eb33838e4ff/whitelist.txt) with service domains from [Koridor's `whitelist` and `category-ru`](https://github.com/mvrvntn/routing/tree/ac78c53c390be11d238f61ecd1106027ce131f7e/data). The list omits entries already covered by .ru or .рф and excludes IP ranges, shared hosting suffixes, and external IP checkers. Both sources use the MIT license. The notices are included in the application resources and in [ru-direct-domains.LICENSE](ru-direct-domains.LICENSE).
