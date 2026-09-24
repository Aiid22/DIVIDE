# DIVIDE：发表导向的研究制品

[English](README.md) | [中文](README.zh-CN.md)

我们在论文 *Divide and Conquer: Secret Discovery Beyond Text-Only Scanning* 中提出 DIVIDE，即“载体定位 → 秘密恢复 → 层次化离线验证”的三阶段方法。本仓库提供该方法的当前 Python 实现，对应论文第 2–3 页的 Fig. 2、Table 1、Algorithm 1、Equation (1) 与 §2.1–2.3。

本仓库就是 DIVIDE 的当前实际实现。

## 方法映射

```text
输入文件/项目
  └─ CarrierHandler registry
       签名 + MIME + 结构一致性 → CarrierObject / CarrierRecord
       递归展开与统一资源预算 → 父对象、字段、页码、bbox、偏移和哈希
          └─ Recovery
               编码推断与规范化 → 有界递归 Base64/Base64URL/Hex/URL 解码
               OCR 几何重组 → Equation (1) 规则约束 beam search
               RelatedGroup → RecoveryPlan 校验 → 确定性执行器
                  └─ Hierarchical Verification
                       类型/版本 → 硬格式 → checksum → 精确占位符
                       → 字段和代码噪声 → 载体/上下文/恢复评分
                          └─ 脱敏 schema-2.0 报告 / RQ1 / RQ2
```

逐项对应关系和证据边界见[方法映射](docs/METHOD_MAPPING.md)。

## 载体能力矩阵

我们的注册表为 Table 1 中每类格式提供独立 handler 契约：

- 文本：源代码、TXT、JSON、CSV、XML、YAML、SVG、PEM。
- 归档：ZIP、TAR、GZIP、7z、RAR、JAR、APK、RPM、ISO。
- 文档：DOC/DOCX、XLS/XLSX、PPT/PPTX、ODF、EPUB、RTF、Outlook MSG。
- 二进制与媒体：ELF、PE、Mach-O、WASM、字体、音频、视频。
- 图片：PNG、JPEG、GIF、TIFF、WebP、ICO、PSD。
- 其他：PDF、SQLite、GNU MO/Gettext、未知二进制 ASCII/UTF-16 回退。

`divide capabilities --json` 根据当前环境报告 `full`、`partial`、`fallback` 或 `unavailable`。需要可选解析库或外部解码器的格式不会被静默标为完整支持。RAR 和视频等格式可能只有元数据或字符串回退；图片 OCR 还取决于已配置的 OCR 引擎和语言数据。

## 目录

```text
DIVIDE/
├── README.md                     # 默认英文入口
├── README.zh-CN.md               # 中文入口
├── requirement.txt               # 兼容依赖范围
├── constraints.txt               # 可重复实验固定版本
├── requirements-dev.txt          # 测试与审计依赖
├── docs/                          # 双语方法和审计记录
├── examples/                      # 全部是不可用的合成示例
├── src/divide/
│   ├── localization/             # handler registry 与递归载体提取
│   ├── recovery/                 # 编码、beam、RelatedGroup、RecoveryPlan
│   ├── rulesets/                 # 我们的规则、Gitleaks 快照和 checksum
│   ├── verification/             # 层次化决策与来源级去重
│   ├── evaluation/               # manifest、RQ1 指标、RQ2 消融、baseline
│   └── schemas/                  # 报告与恢复计划 JSON Schema
└── tests/                         # 单元、安全和 handler contract 测试
```

## CLI 与中英文切换

默认展示语言为英文。所有命令均接受 `--language en|zh`（或 `--lang en|zh`）；也可以通过 `default_rules.yaml` 中的 `output.language` 持久设置默认语言。为保持 schema 稳定，JSON 字段名始终使用英文，但输出会记录 `display_language`。

```bash
divide scan TARGET --output report.json
divide scan TARGET --output report.json --language zh
divide capabilities --json --language zh
divide benchmark MANIFEST --output benchmark.json --language zh
divide ablate MANIFEST --output ablation.json --language zh
divide rules audit --output rules-audit.json --language zh
```

扫描参数包括 `--config`、资源限制、`--ocr/--no-ocr`、`--timeout`、本地 OpenAI-compatible planner 参数和 `--show-secrets`。默认报告只给出掩码值与 SHA-256 指纹；只有显式使用 `--show-secrets` 才会写出明文。

默认配置位于 `src/divide/default_rules.yaml`。资源限制包括递归深度、单对象/总展开大小、归档成员数与压缩比、图片像素、媒体帧、SQLite 行数与 VM 步数、OCR 页数、解码深度/输出、beam 宽度和恢复计划预算。

## 恢复计划与 Qwen 档案

默认 planner 为 `null`，状态为 `model_unavailable`，不会调用模型。我们为 Qwen3-32B-AWQ 经 vLLM 暴露的 OpenAI-compatible 接口提供版本化配置档案，并将提示词版本固定为 `divide-recovery-plan-v1`。模型只能提交引用现有记录的 `concat`、`decode`、受限 `substitute` 计划。只有通过 JSON Schema、引用集合、单赋值、操作白名单、预算和唯一输出校验后，我们的本地确定性执行器才会运行计划。

## 规则和离线验证

我们的高置信核心规则具有版本、来源、格式约束、测试向量和许可证元数据；另固定了 Gitleaks v8.30.1 的完整上游配置快照（commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`，内容 SHA-256 记录在 snapshot manifest），转换 `secretGroup`、entropy、keywords、全局/规则级 allowlists、stopwords 和路径规则。我们的规则优先，跨 provider 冲突保留双方 provenance。

GitHub token checksum 插件实现 CRC32 → 使用 `0-9A-Za-z` 字母表的 Base62 → 六位后缀与左侧补零。字母表仍作为显式构造参数保留，以支持格式版本管理。

## 数据集与实验口径

我们不将研究数据集提交到仓库。manifest 只接收 `artifact_id`、`project_id`、相对路径、文件 SHA-256、MIME、秘密 SHA-256 指纹和位置标注，示例见 `examples/dataset-manifest.example.json`。

`benchmark` 同时计算：

- raw occurrence：项目、载体、指纹和位置组成的出现实例；
- project unique：`(project_id, secret fingerprint)`，只在评测层归一化。

两种口径均输出 precision、recall、F1、FDR 和 latency。`ablate` 固定运行 `full`、`no-media`、`no-recovery`、`no-post-filter`。结果包含代码版本、配置/规则/能力矩阵哈希、随机种子、模型档案、manifest 哈希和环境信息。Gitleaks、TruffleHog、KEYSENTINEL、Qwen LLM/VLM baseline 本轮仅提供显式 `unavailable` 接口，不会伪造结果。

## schema 2.0 输出片段

```json
{
  "schema_version": "2.0",
  "display_language": "zh",
  "provenance": {"code_revision": "..."},
  "capabilities": [{"handler_id": "rar", "status": "fallback"}],
  "candidate_decisions": [{"accepted": false, "stage": "hard:checksum"}],
  "ablation_profile": "full",
  "summary": {"findings": 0},
  "findings": []
}
```

损坏文件、加密归档、资源超限、依赖缺失和恶意恢复计划会进入 warning/decision，不中止整个扫描。

## 安全边界

- 我们在临时展开前检查归档成员路径，不向扫描目标写文件，并默认跳过符号链接。
- SQLite 使用只读 immutable 模式及查询预算；XML 使用 `defusedxml`。
- 解码、OCR beam、规划操作和输出都有上限；模型文本从不作为代码执行。
- 示例和测试只使用不可用的合成秘密；评测 manifest 保存指纹，不保存秘密明文。
- `--show-secrets` 会把明文写入报告，只应在受控实验环境使用。

## 研究制品边界

本仓库包含 DIVIDE 的当前实际实现。我们有意不随仓库分发研究数据集、私有部署配置、模型权重或外部 baseline 可执行文件。Table 1 的“完整适配器矩阵”表示每种格式都有明确 handler 和能力契约，不表示所有环境均有完整后端。
