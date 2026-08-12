# Documentation Index

本目录保存当前项目的正式目标文档。

这些文档定义项目应该达到的目标形态、架构边界、数据契约、行为建模方式、检测评分方式、AI 使用边界和最终质量标准。

## 文档职责

| 文档                                  | 职责                                                         |
| ------------------------------------- | ------------------------------------------------------------ |
| `00_project_baseline.md`              | 定义项目顶层需求、目标边界和主线约束。                       |
| `01_product_shape.md`                 | 定义产品目标形态和核心页面。                                 |
| `02_architecture_overview.md`         | 定义系统主链路、组件职责和边界。                             |
| `03_data_contract.md`                 | 定义 Kafka topic、标准日志、异常事件、baseline、AI 研判和反馈的数据契约。 |
| `04_clickhouse_schema.md`             | 定义 ClickHouse 表结构、字段落库规则、分区、排序键和 TTL。   |
| `05_behavior_modeling_spec.md`        | 定义五W1H、T+1 日级特征、周期 baseline 和审核覆盖层。        |
| `06_detection_and_scoring_spec.md`    | 定义规则检测、baseline 偏离、评分、风险等级和 reason codes。 |
| `07_ai_judgement_feedback_spec.md`    | 定义 AI 研判输入、输出和反馈机制。                           |
| `08_api_contract.md`                  | 定义 FastAPI 对外接口和前端使用契约。                        |
| `09_data_generation_and_scenarios.md` | 定义数据规模、日志类型、场景注入和数据质量要求。             |
| `10_final_quality_criteria.md`        | 定义项目达到目标形态时应满足的最终质量标准。                 |
| `11_operations_and_acceptance_spec.md` | 定义周期任务、质量门禁、场景评测和高危通知的运营闭环。       |
| `12_reproducible_anomaly_scenarios.md` | 定义脱敏、可复现的异常检测场景与运行方式。                 |
| `13_detection_acceptance_report.md` | 记录异常检测 A 模块的场景、稳定性与去重验收结果。          |
| `12_engineering_quality_audit.md`     | 定义技术债基线、修复优先级和质量验证命令。                   |

## ADR

架构决策记录位于 `docs/adr/`。

ADR 用于记录会长期影响项目结构的核心决策。
如果后续新增主存储、改变数据链路、调整 AI 反馈机制、修改 baseline 建模方式，应新增或更新 ADR。
