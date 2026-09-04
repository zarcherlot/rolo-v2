status: active
authority: guide

# LanderPi Agent Journey MVP 现场走查

1. 在设备周围确认急停、网络、地图区域和数据目录，启动 loopback runtime。
2. 执行 `rolo target inspect-profile --profile mentorpi` 和新鲜 `rolo probe`，保存
   Probe manifest、Tool Surface、RKB snapshot、MHS inventory 及 digest。
   若 profile 使用受限的 enrollment key（`authorized_keys` 配置了强制
   `target-evidence collector-run`），通用 `uname` 检查会被目标端忽略并等待超时；
   这表示传输认证正常但 shell 检查路径不适用。请改用
   `rolo probe target-evidence preflight --robot-id mentorpi` 或 `collect` 验证 pinned
   collector，不要为通过通用检查而移除强制命令限制。
3. 通过 `register_catalog` 或 HTTP adapter 发布 `TargetCatalog`。先运行旋转只读预检，确认
   `/cmd_vel`/`/odom` 路由和目标证据 digest 一致。如果目录没有经过独立授权的
   `agent_callable=true` 旋转写工具，任何旋转 Trace 创建会返回
   `BLOCKED: physical rotation capability not observed`，现场流程必须停止。
   预检命令为 `python scripts/rotation_mvp_readiness.py --evidence <verified-bundle.json>`；
   返回 `READY_FOR_SUPERVISED_REVIEW` 只表示允许进入人工复核，不会驱动底盘。
4. 为 Trace 创建带 TTL 和预算的 session；每次调用只使用 catalog 中的工具。错误必须
   关联本次 session 的 evidence，并最多进行有界诊断/恢复尝试。
5. 在 `SUPERVISED_FIELD_DEBUG` 下执行实验性写工具时，必须提供 operator identity、
   `safety_confirmed=true`、超时、停止/取消和结果读回；`UNATTENDED_REMOTE` 在 MVP 中拒绝。
6. 使用 `examples/chassis-rotation-10.json` 作为离线格式样例。现场 runner 应从设备路径加载同
   格式的十条用例，并调用 `CertificationRunner` 生成 JSON、Markdown 和 artifact index。
7. 归档 `.rolo/mvp/<run_id>/` 下的 session、events、evidence、报告和索引，用 SHA-256
   校验回放；所有 UNKNOWN、BLOCKED、重试和人工介入均保留在报告中。

该走查只适用于有人在场的实验调试窗口，不构成功能安全或无人值守授权。当前旋转实现只生成
有界 dry-run 计划和读回要求，不直接发布 `/cmd_vel` 或调用执行器。
