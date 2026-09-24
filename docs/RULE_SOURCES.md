# 规则来源与版本

## DIVIDE core 2026.09.1

覆盖 AWS、GitHub、GitLab、Slack、Stripe、Google API key、PEM 私钥及通用敏感字段赋值。规则定义位于 `default_rules.yaml`，是为复现工程编写的高置信近似，不声称来自论文作者。每条编译后规则携带 provider/version/source/license 字段。

## Gitleaks v8.30.1

- 上游配置：<https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml>
- 上游项目：<https://github.com/gitleaks/gitleaks>
- 许可证：MIT，副本位于 `src/divide/rulesets/data/LICENSE.gitleaks`
- 固定 commit：`83d9cd684c87d95d656c1458ef04895a7f1cbd8e`。
- 当前随附文件：完整上游 `config/gitleaks.toml`，内容 SHA-256 为 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`；`rules audit` 再计算并核对 manifest。
- 转换字段：`regex`、`secretGroup`、`entropy`、`keywords`、全局及规则级 `allowlists.regexes`、`allowlists.paths`、`stopwords`。

核心规则 priority 高于导入规则；相同 pattern 的跨 provider 冲突不会覆盖，而会在 audit 中保留两方来源。

## GitHub token checksum

算法来源：<https://github.blog/engineering/behind-githubs-new-authentication-token-formats/>。该来源说明 CRC32、Base62、末六位和补零，但本实现仍把字母表登记为 EA-005，等待独立供应商测试向量确认。
