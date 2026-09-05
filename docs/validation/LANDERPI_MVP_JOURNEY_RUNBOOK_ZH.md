status: active
authority: guide

# LanderPi Agent Journey MVP 现场走查

1. 在设备周围确认急停、网络、地图区域和数据目录，启动 loopback runtime。
2. 执行 `rolo target inspect-profile --profile mentorpi` 和新鲜 `rolo probe`，保存
   Probe manifest、Tool Surface、RKB snapshot、MHS inventory 及 digest。
   Probe、Trace、Certify 和已注册 Tool 共用 profile 的普通 SSH 登录。目标端只需提供
   已存在的 Python/驱动运行时；Rolo 通过 stdin 发送受约束的 Probe Runner 或 Harness，
   不生成额外 key，也不依赖强制命令入口。
3. 通过 `register_catalog` 或 HTTP adapter 发布 `TargetCatalog`。先运行旋转只读预检，确认
   `/cmd_vel`/`/odom` 路由和目标证据 digest 一致。如果目录没有目标绑定、已注册且
   `agent_callable=true` 的旋转实验性 Tool，任何旋转 Trace 创建会返回
   `BLOCKED: physical rotation capability not observed`，现场流程必须停止。
   预检命令为 `python scripts/rotation_mvp_readiness.py --evidence <verified-bundle.json>`；
   返回 `READY_FOR_SUPERVISED_REVIEW` 只表示允许进入人工复核，不会驱动底盘。
4. 为 Trace 创建带 TTL 和预算的 session；每次调用只使用 catalog 中的工具。错误必须
   关联本次 session 的 evidence，并最多进行有界诊断/恢复尝试。
5. 在 `SUPERVISED_FIELD_DEBUG` 下执行实验性写工具时，需要用户确认现场安全、
   超时、停止/取消和结果读回。operator ID 仅为可选审计备注，缺省保存 null，
   不能由 Harness 虚构身份；`UNATTENDED_REMOTE` 在 MVP 中拒绝。
6. 使用 `examples/chassis-rotation-10.json` 作为离线格式样例。现场 runner 应从设备路径加载同
   格式的十条用例，并调用 `CertificationRunner` 生成 JSON、Markdown 和 artifact index。
7. 归档 `.rolo/mvp/<run_id>/` 下的 session、events、evidence、报告和索引，用 SHA-256
   校验回放；所有 UNKNOWN、BLOCKED、重试和人工介入均保留在报告中。

该走查只适用于有人在场的实验调试窗口，不构成功能安全或无人值守授权。旋转动作只能经已注册
的实验性 Tool 进入目标 binding；MHS 只提供可选驱动上下文，Rolo 不开放任意 Shell、topic
publish、argv 或底层旁路。

## 统一目标授权

MVP 使用目标已有的普通用户 SSH 登录配置和一条统一目标连接，同时授权 Probe、Trace、
Certify 及已注册 Tool 执行。Rolo 不生成或安装额外 key，也不要求目标机安装 Rolo；只通过
目标已有 runtime/driver 执行受 binding 约束的 Harness。执行器不接受任意 shell、topic 或
argv。

配置示例：

```text
rolo target profile init ssh://pi@<host>/home/pi/rolo --robot mentorpi \
  --credential-ref ssh-agent:default
```

缺少用户 SSH 登录、目标端 Python 或驱动依赖时，旋转结果必须为
`BLOCKED: TARGET_EXECUTION_CHANNEL_UNAVAILABLE`，不得回退到只读采集通道。
