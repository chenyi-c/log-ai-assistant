# Log AI Assistant

本项目是一个面向企业安全日志分析的 AI 助手原型。

项目目标是构建从日志采集、结构化处理、ClickHouse 存储、行为基线建模、异常检测、AI 研判反馈到前端工作台的完整安全分析系统。

## My Contribution / 共创说明

本项目为团队共创项目。我在项目中主要负责 **异常检测链路（A 模块）**，核心工作集中在：

- 将已经标准化入库的 `security_logs` 转换为可供前端、AI 研判和运营日报使用的 `anomaly_events`。
- 设计并实现基于 `RuleEngine` 的异常规则判断，包括登录失败聚集、凭证填充、新来源 IP、非工作时间登录、敏感资源访问、横向移动、大量下载/导出等场景。
- 参与定义异常事件数据结构，覆盖 `risk_level`、`risk_score`、`reason_codes`、`rule_hits`、`baseline_deviations`、`evidence`、`related_event_ids` 和 `ai_status` 等字段。
- 将规则强度、行为基线偏离、敏感行为、事件关联和反馈修正纳入风险评分，让检测结果不只是“命中规则”，而是能解释、能排序、能进入后续 AI 研判。
- 打通 `ClickHouse security_logs -> anomaly-detector -> anomaly_events -> frontend / AI judgement / reports` 的中间链路，支撑团队其他成员的数据展示、研判和闭环反馈工作。

这段工作让我完整参与了一个从日志流处理到安全异常事件建模的后端工程链路，也锻炼了我把规则检测、行为基线、风险评分和可解释证据包结合到实际系统中的能力。

## 可复现异常检测演示

我负责的 A 模块可以独立用一组固定、脱敏的场景复跑：

```text
安全日志样例 -> RuleEngine -> AnomalyEvent -> FastAPI GET /api/v1/anomalies
```

场景定义位于 `tests/fixtures/reproducible_anomaly_scenarios_v1.json`，仅使用虚拟账号、资源名与 TEST-NET 保留网段。场景覆盖：登录失败突增、凭证填充、高频 API 调用、敏感资源访问、新来源登录后敏感访问，以及两类正常行为对照。每项都声明输入序列、预期 `risk_level`、`reason_codes`、`evidence` 和 `related_event_ids`；测试会用真实 `RuleEngine` 生成 `AnomalyEvent`，再经 FastAPI 查询路由校验返回契约。

运行最小演示：

```bash
docker compose run --rm tester pytest -q tests/test_reproducible_anomaly_scenarios.py
```

该测试是固定规则样例的回归验证，不代表模型准确率、真实企业数据效果或生产性能。完整系统启动后可通过以下接口查看已入库的异常事件：

```bash
curl http://localhost:8000/api/v1/health
curl "http://localhost:8000/api/v1/anomalies?limit=20"
```

阶段 2 的场景验收、稳定 ID、增量读取、warmup 与去重验证见 `docs/13_detection_acceptance_report.md`。其中明确区分已验证的 A 模块行为与尚未进行的集群负载验证。

## 当前主链路

Filebeat -> Kafka -> Flink -> ClickHouse -> FastAPI -> React

ClickHouse 是当前唯一主存储和分析引擎。
Elasticsearch 不再作为当前目标形态的一部分。

## 正式目标文档

当前项目目标形态、架构约束、数据契约、行为建模方式、AI 使用边界和最终质量标准以 `docs/` 为准。

建议优先阅读：

- `docs/00_project_baseline.md`
- `docs/02_architecture_overview.md`
- `docs/03_data_contract.md`
- `docs/04_clickhouse_schema.md`
- `docs/05_behavior_modeling_spec.md`
- `docs/06_detection_and_scoring_spec.md`
- `docs/07_ai_judgement_feedback_spec.md`
- `docs/09_data_generation_and_scenarios.md`
- `docs/10_final_quality_criteria.md`
- `docs/11_operations_and_acceptance_spec.md`

## 文档索引

完整文档索引见：

- `docs/README.md`

架构决策记录见：

- `docs/adr/README.md`

## 正式运行环境

项目正式运行环境以 Docker Compose 为准。开发者本机只要求安装：

- Git
- Docker / Docker Compose
- 编辑器
- 浏览器

不要求组员本机安装 Miniconda、Python、Node、Flink、Kafka、ClickHouse 或 Filebeat。本地 Python、Node 或 Conda 环境只能作为个人开发便利，不作为项目正式运行依赖。

## Docker-first 启动

首次启动：

```bash
cp .env.example .env
docker compose up --build
```

如果宿主机配置的 Docker Hub 镜像源不可用，构建可能在 `python:3.11-slim`、`node:20-alpine` 等基础镜像 metadata 阶段失败。此时在 `.env` 中把 `PYTHON_BASE_IMAGE`、`NODE_BASE_IMAGE` 或 `KAFKA_IMAGE`、`CLICKHOUSE_IMAGE`、`FLINK_IMAGE`、`FILEBEAT_IMAGE` 改为当前网络可访问的镜像地址，或改为本机已预拉取并重新 tag 的镜像名。

默认 Compose 会拉起当前正式运行基线中的主要服务：

| 服务 | 作用 | 默认访问 |
| --- | --- | --- |
| `kafka` | 流式传输和缓冲层 | `localhost:9092` |
| `flink-jobmanager` / `flink-taskmanager` | Flink 运行环境 | `http://localhost:8081` |
| `flink-submit` | 提交正式 `raw_logs -> parsed_logs` Flink 作业 | 容器内运行 |
| `clickhouse` | 主存储和分析引擎 | `http://localhost:8123` |
| `clickhouse-migrate` | 幂等应用 ADR-010 等增量表结构 | 一次性容器 |
| `filebeat` | 采集 `logs/*.log` 并写入 Kafka `raw_logs` | 容器内运行 |
| `anomaly-detector` | 持续检测 `security_logs` 并写入 `anomaly_events` | 容器内运行 |
| `backend` | FastAPI API 层 | `http://localhost:8000` |
| `frontend` | React + Vite 工作台 | `http://localhost:5173` |
| `log-generator` | 小规模持续生成多源日志样例 | 写入 `logs/` |

默认启动包含 Flink，以保持正式主链路为 `Filebeat -> Kafka -> Flink -> ClickHouse -> FastAPI -> React`。Elasticsearch 和 Kibana 仅在 `legacy-es` profile 中，不进入默认主链路。

如果 `flink:1.18.1` 在当前网络不可拉取，可以在 `.env` 中把 `FLINK_IMAGE` 改为可访问镜像地址，或先在本机预拉取后重新 tag 为 `flink:1.18.1`。

如果使用 Docker Desktop 或脚本执行“拉取全部服务镜像”，可能会触发 legacy profile 中的服务。只拉取默认运行链路时，显式指定服务更稳：

```bash
docker compose pull kafka kafka-init clickhouse filebeat backend frontend log-generator
docker compose up --build kafka kafka-init clickhouse log-generator filebeat flink-jobmanager flink-taskmanager flink-submit anomaly-detector backend frontend
```

默认日志生成器是小流量开发配置，避免压垮普通开发机。大规模日志生成不随默认启动运行，需要显式启用 profile：

```bash
docker compose --profile scale up --build
```

`scale` profile 默认生成速率为 `25 条/秒`，约 `1500 条/分钟`。按当前多源 JSON 日志平均约 700B/条估算，约等于 `1.5GB/day` 原始日志量；如果需要更贴近 `1GB/day`，可在 `.env` 中设置 `LOG_GENERATOR_SCALE_BATCH_SIZE=17`。

默认启动通过 Flink 作业把 `raw_logs` 规范化成 `parsed_logs`，ClickHouse 通过 Kafka 引擎表把 `parsed_logs` 落入 `security_logs`。

`anomaly-detector` 默认每 1 秒执行一轮、每轮最多读取 2000 条日志，用于跟上 scale profile 的数据速率。若检测仍滞后，可继续调高 `.env` 中的 `ANOMALY_DETECTOR_BATCH_SIZE`。

`anomaly-detector` 在 Compose 持续运行模式下会使用 `ANOMALY_DETECTOR_LOOKBACK_MINUTES` 对最近日志执行启动 warmup：只恢复规则滑动窗口和稳定 anomaly id 去重状态，不把 warmup 期间的历史异常重复写入 `anomaly_events`。

`raw-to-parsed` 仅作为故障隔离或本地 fallback 工具保留在 `fallback` profile 中，不属于默认正式主链路。

测试入口不随默认启动运行，可以按需执行：

```bash
docker compose run --rm tester
```

Elasticsearch / Kibana 仅保留在 `legacy-es` profile 中，供旧代码兼容或迁移对照使用，不属于当前正式主链路。
