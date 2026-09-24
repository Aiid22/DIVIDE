# Reproducibility status

[English](REPRODUCIBILITY_STATUS.en.md) | [中文](REPRODUCIBILITY_STATUS.md)

**UNVALIDATED**

我们在本次交付中已生成方法实现、能力契约、规则审计、数据 manifest、指标/消融框架和测试源码，但没有执行：

- pytest 或静态检查；
- 论文/用户数据集的转换和评测；
- Qwen3-32B-AWQ 或任何 LLM/VLM 推理；
- Gitleaks、TruffleHog、KEYSENTINEL baseline；
- 性能、资源安全或跨平台实验。

我们已经固定完整 Gitleaks 快照、commit SHA 和内容哈希。升级状态前，我们仍至少需要：冻结实际执行环境；执行全套单元/安全/contract 测试；用隔离开发集锁定 EA 参数；在保留测试集上运行 RQ1 与四组 RQ2；核对 raw occurrence 和 project unique 口径；记录失败样本与能力降级；完成可重复运行审计。
