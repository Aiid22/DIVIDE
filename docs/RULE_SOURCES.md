# 规则来源与版本

[English](RULE_SOURCES.en.md) | [中文](RULE_SOURCES.md)

## DIVIDE core 2026.09.1

我们的当前核心规则覆盖 AWS、GitHub、GitLab、Slack、Stripe、Google API key、PEM 私钥及通用敏感字段赋值。规则定义位于 `default_rules.yaml`，每条编译后规则携带 provider/version/source/license 字段。

## Gitleaks v8.30.1

- 上游配置：<https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>
- 上游项目：<https://github.com/gitleaks/gitleaks>
- 许可证：MIT，副本位于 `src/divide/rulesets/data/LICENSE.gitleaks`
- 固定 commit：`83d9cd684c87d95d656c1458ef04895a7f1cbd8e`。
- 当前随附文件：完整上游 `config/gitleaks.toml`，内容 SHA-256 为 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`；`rules audit` 再计算并核对 manifest。
- 转换字段：`regex`、`secretGroup`、`entropy`、`keywords`、全局及规则级 `allowlists.regexes`、`allowlists.paths`、`stopwords`。

我们的核心规则 priority 高于导入规则；相同 pattern 的跨 provider 冲突不会覆盖，而会在 audit 中保留两方来源。

## GitHub token checksum

算法来源：<https://github.blog/engineering/behind-githubs-new-authentication-token-formats/>。当前实现使用 CRC32、`0-9A-Za-z` Base62 字母表、末六位和左侧补零。
