# DIVIDE：发表导向的方法忠实复现源码

本仓库依据 *Divide and Conquer: Secret Discovery Beyond Text-Only Scanning* 第 2–3 页的 Fig. 2、Table 1、Algorithm 1、Equation (1) 与 §2.1–2.3，实现“载体定位 → 秘密恢复 → 层次化离线验证”的非官方 Python 复现包。

当前复现状态固定为 **UNVALIDATED**：源码、测试源码、数据接口和实验协议已经提供，但本次交付没有执行测试、静态检查、模型推理或数据集评测，也不声称复现论文数值。论文未公开的阈值、权重、提示词及部分解析细节均登记为 `engineering_assumption`。

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

逐项对应关系和证据边界见 [METHOD_MAPPING.md](docs/METHOD_MAPPING.md)，工程近似见 [ASSUMPTIONS.md](docs/ASSUMPTIONS.md)。

## 载体能力矩阵

注册表为 Table 1 中每类格式提供独立 handler 契约：

- 文本：源代码、TXT、JSON、CSV、XML、YAML、SVG、PEM。
- 归档：ZIP、TAR、GZIP、7z、RAR、JAR、APK、RPM、ISO。
- 文档：DOC/DOCX、XLS/XLSX、PPT/PPTX、ODF、EPUB、RTF、Outlook MSG。
- 二进制与媒体：ELF、PE、Mach-O、WASM、字体、音频、视频。
- 图片：PNG、JPEG、GIF、TIFF、WebP、ICO、PSD。
- 其他：PDF、SQLite、GNU MO/Gettext、未知二进制 ASCII/UTF-16 回退。

`divide capabilities --json` 根据当前环境报告 `full`、`partial`、`fallback` 或 `unavailable`。需要可选解析库或外部解码器的格式不会被静默标为完整支持。RAR 和视频等格式可能只有元数据/字符串回退；图片 OCR 还取决于已配置的 OCR 引擎和语言数据。

## 目录

```text
DIVIDE/
├── README.md
├── requirement.txt              # 兼容范围
├── constraints.txt              # 可复现实验固定版本
├── requirements-dev.txt         # 测试/审计依赖
├── docs/
│   ├── METHOD_MAPPING.md
│   ├── ASSUMPTIONS.md
│   ├── RULE_SOURCES.md
│   ├── THIRD_PARTY_NOTICES.md
│   └── REPRODUCIBILITY_STATUS.md
├── examples/                     # 全部是不可用的合成示例
├── src/divide/
│   ├── localization/             # handler registry 与递归载体提取
│   ├── recovery/                 # 编码、beam、RelatedGroup、RecoveryPlan
│   ├── rulesets/                 # 自建规则、Gitleaks 快照和 checksum
│   ├── verification/             # 层次化决策与来源级去重
│   ├── evaluation/               # manifest、RQ1 指标、RQ2 消融、baseline
│   └── schemas/                  # RecoveryPlan 与 manifest JSON Schema
└── tests/                        # 只生成，未执行
```

## CLI

```bash
divide scan TARGET --output report.json
divide capabilities --json
divide benchmark MANIFEST --output benchmark.json
divide ablate MANIFEST --output ablation.json
divide rules audit --output rules-audit.json
```

扫描参数包括 `--config`、`--max-depth`、`--max-object-size`、`--max-expanded-size`、`--max-compression-ratio`、`--ocr/--no-ocr`、`--timeout`、本地 OpenAI-compatible planner 参数和 `--show-secrets`。默认报告只给出掩码值与 SHA-256 指纹；只有显式使用 `--show-secrets` 才会写出明文。

默认配置位于 `src/divide/default_rules.yaml`。资源限制包括递归深度、单对象/总展开大小、归档成员数与压缩比、图片像素、媒体帧、SQLite 行数与 VM 步数、OCR 页数、解码深度/输出、beam 宽度和恢复计划预算。

## 恢复计划与 Qwen 档案

默认 planner 为 `null`，状态为 `model_unavailable`，不会调用模型。配置档案预留 Qwen3-32B-AWQ 经 vLLM 暴露的 OpenAI-compatible 接口；固定提示词版本为 `divide-recovery-plan-v1`。模型只能提交引用现有记录的 `concat`、`decode`、受限 `substitute` 计划。JSON Schema、引用集合、单赋值、操作白名单、预算和唯一输出均通过后，才由本地执行器运行。

## 规则和离线验证

高置信核心规则具有版本、来源、格式版本、约束和许可证元数据；另固定了 Gitleaks v8.30.1 的完整上游配置快照（commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`，内容 SHA-256 记录在 snapshot manifest），转换 `secretGroup`、entropy、keywords、全局/规则级 allowlists、stopwords 和路径规则。自建规则优先，冲突保留双方 provenance。`tools/vendor_gitleaks_snapshot.py` 可用于经独立哈希确认后重新生成快照。

GitHub token checksum 插件实现 CRC32 → Base62 → 六位后缀与左侧补零。GitHub 公开了算法，但所引用说明没有固定字母表；默认字母表因此登记为 EA-005，并保持可配置。正式论文结果需要以独立供应商向量再次确认。

## 数据集与实验口径

数据集不进入仓库。manifest 只接收 `artifact_id`、`project_id`、相对路径、文件 SHA-256、MIME、秘密 SHA-256 指纹和位置标注。示例见 `examples/dataset-manifest.example.json`。

`benchmark` 同时计算：

- raw occurrence：项目、载体、指纹和位置组成的出现实例；
- project unique：`(project_id, secret fingerprint)`，只在评测层归一化。

两种口径均输出 precision、recall、F1、FDR 和 latency。`ablate` 固定运行 `full`、`no-media`、`no-recovery`、`no-post-filter`。结果包含代码版本、配置/规则/能力矩阵哈希、随机种子、模型档案、manifest 哈希和环境信息。Gitleaks、TruffleHog、KEYSENTINEL、Qwen LLM/VLM baseline 本轮仅提供显式 `unavailable` 接口，不会伪造结果。

## schema 2.0 输出片段

```json
{
  "schema_version": "2.0",
  "provenance": {"reproduction_status": "UNVALIDATED"},
  "capabilities": [{"handler_id": "rar", "status": "fallback"}],
  "candidate_decisions": [{"accepted": false, "stage": "hard:checksum"}],
  "ablation_profile": "full",
  "engineering_assumptions": ["EA-001: beam width B=64 ..."],
  "summary": {"findings": 0},
  "findings": []
}
```

损坏文件、加密归档、资源超限、依赖缺失和恶意恢复计划会进入 warning/decision，不中止整个扫描。

## 安全边界

- 归档成员路径在落入临时目录前检查，不向扫描目标写文件；符号链接默认跳过。
- SQLite 使用只读 immutable 模式及查询预算；XML 使用 `defusedxml`。
- 解码、OCR beam、规划操作和输出都有上限；模型文本从不作为代码执行。
- 示例和测试只应使用不可用合成秘密。评测 manifest 保存指纹，不保存秘密明文。
- `--show-secrets` 会把明文写入报告，只应在受控实验环境使用。

## 与论文作者实现的边界

本仓库复现论文公开的方法结构，不包含作者源代码、数据集、完整规则全集、私有提示词或训练模型。Table 1 的“完整矩阵”表示每种格式都有 handler 和能力契约，不表示所有环境均有完整后端。测试、数据集评测、模型实验和基线运行完成前，本交付物只能称为“发表导向的方法忠实复现源码”。
