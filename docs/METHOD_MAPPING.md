# 论文方法—实现映射

[English](METHOD_MAPPING.en.md) | [中文](METHOD_MAPPING.md)

我们用本表记录论文方法与参考原型的逐项对应关系及证据边界。

| 论文构件 | 实现入口 | 忠实性说明 |
|---|---|---|
| Fig. 2 三阶段架构 | `pipeline.py` | 定位、恢复、验证按固定阶段串联，保留 provenance。 |
| Table 1 载体矩阵 | `localization/registry.py` | 每类格式均有 handler、probe、能力状态和显式降级。 |
| 类型真实性与结构校验 | `localization/detector.py` | 签名与内部结构优先，扩展名只作低置信辅助。 |
| 递归载体提取 | `localization/localizer.py` | 统一深度、大小、展开量、压缩比、成员数与超时预算。 |
| §2.2 编码推断 | `recovery/encoding.py` | BOM、严格解码、字符分布和可打印比例联合；聚合权重为 EA-007。 |
| §2.2 有界解码 | `recovery/decoder.py` | 标准/URL-safe Base64、Hex、URL，逐步输入/输出哈希与深度。 |
| Equation (1) | `constrained_ocr_beam` | 生成中应用前缀、长度、字符集约束，输出不超过 B；B=64 为 EA-001。 |
| 结构相关分组 | `recovery/fragments.py` | 使用父对象、字段关系、表达式/位置顺序生成 `RelatedGroup`。 |
| Algorithm 1 计划恢复 | `recovery/planner.py` | 固定 schema、引用/操作/预算验证、确定性执行、最多一个计划。 |
| §2.3 层次化验证 | `verification/verifier.py` | 类型/版本→硬约束→checksum→占位符→语境→评分。 |
| 规则语料 | `rulesets/` | 核心规则和完整固定 Gitleaks v8.30.1 配置均保留来源、commit、内容哈希和许可证。 |
| GitHub checksum | `rulesets/checksums.py` | CRC32→Base62→末六位；字母表为显式 EA-005。 |
| RQ1/RQ2 | `evaluation/` | raw occurrence、project unique 与四种固定消融。 |

本表只陈述源码对应关系，不构成结果验证。我们的当前状态见 `REPRODUCIBILITY_STATUS.md`。
