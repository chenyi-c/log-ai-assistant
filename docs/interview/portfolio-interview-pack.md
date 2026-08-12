# Log AI Assistant 面试包

_用于 3 分钟调查演示、失败复盘和 AI 应用后端追问。_

---

## 🎯 一句话定位

这是规则优先、证据驱动的日志调查后端：异常结论必须能追溯到固定输入、原因码、阈值、脱敏证据和人工反馈，模型不能替代确定性事实。

## 📋 三分钟讲解

1. 运行固定脱敏场景，展示稳定 `anomaly_id`、原因码和风险等级
2. 打开调查证据链，说明规则阈值、相关事件和窄范围 ATT&CK 引用
3. 回放一次 `pending -> confirmed` 人工复核
4. 对照提交的 [Markdown](../evidence/interview-investigation-demo.md) 和 [JSON](../evidence/interview-investigation-demo.json)
5. 指出边界：固定样例不是准确率，脱敏输出不是企业权限系统，模型 API 不是必需路径

## 🔍 三个失败复盘

### Windows 锁只在进程内生效

- 失败：两个 scheduler 进程可同时进入相同幂等键
- 根因：fallback 使用 `threading.Lock`，却被描述为 file lock
- 修复：双子进程测试先复现，再使用 `msvcrt.locking` 固定字节锁；POSIX 继续使用 `fcntl`

### Golden evidence 在 Docker 中缺失

- 失败：本地回归通过，Docker tester 找不到 `docs/evidence`
- 根因：测试镜像和只读挂载没有包含提交的 evidence 文件
- 修复：镜像复制并只读挂载 evidence，同时用构建契约测试约束 Dockerfile/Compose

### “严格 CI”实际永远失败

- 失败：全仓 format check 和 dependency audit 被加入 required gate，但已有债务使 CI 必红
- 根因：把治理目标误写成当前基线
- 修复：pytest、Ruff、Mypy、前端测试和 Docker 测试作为 required；格式与依赖审计保持可见 advisory，并记录精确债务

## 🔄 演示降级

| 层级 | 使用内容 | 证明范围 |
| --- | --- | --- |
| Live | Docker Compose 服务和 API | 完整运行路径 |
| Replay | 固定脱敏场景与 FastAPI 回放 | 调查闭环、幂等和证据，不证明真实检出率 |
| Static | 提交的 JSON/Markdown、CI 与 PR | 可复现证据和工程治理 |

## 💬 高频追问

- 为什么不是让模型直接判断？规则与工具证据可重放，模型只补充候选，不覆盖确定性事实
- 如何保证幂等？稳定异常 ID、成功记录检查和跨进程文件锁共同约束
- 如何避免 evidence 漂移？运行时输出直接与提交的 JSON/Markdown golden 文件比较
- 如何脱敏？只输出白名单字段，用户/IP 去标识化，不保留 `raw_log` 和密钥
- 为什么 audit 不是 required？当前 13 个 Python advisory 需要独立升级验证，不能用永远失败的门禁伪装质量
- Docker 与本地不一致怎么办？Docker 是官方路径；本地 fallback 结果单独标识，不能混称 Docker-backed
