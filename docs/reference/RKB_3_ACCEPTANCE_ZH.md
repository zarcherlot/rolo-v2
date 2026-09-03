<!-- status: active; authority: reference; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# RKB-3 MHS 只读兼容层验收

RKB-3 在 RKB-1/2 的目标绑定证据之上提供 Rolo-owned MHS-compatible SPI。首版统一设备
manifest，并只暴露 `inspect`、`status`、`read` 三个 canonical route：
`mhs://<device_id>/<capability_id>`。旧的
`mhs://sensor/<device_id>/<capability_id>` 仅可作为输入兼容，不会出现在新输出。

每个结果都携带 `manifest_sha256`、driver provider/version/digest、target fingerprint（若
部署提供）、`observed_at`、`fresh_until`、`fact_ids` 和 limitations。manifest 是
`DECLARED`，driver status/read 是 `OBSERVED`；这些结果不会自动升级 capability 为
`ELIGIBLE`/`VERIFIED`，也不表示物理安全。

## 验收

```powershell
python -m pytest tests/test_mhs_hardware.py tests/test_rkb_mhs_readonly.py
python -m compileall -q src tests scripts/mhs_rkb_canary.py
python scripts/check_docs.py
```

本轮不考虑 wheel 安装后导入测试；发布包安装验证属于后续发布工程，不作为 RKB-3 gate。

canary 只在 inspect/status/read 全部成功时原子更新 `latest.json`；失败保留上一份 artifact。
写能力（reset、calibrate、setpoint、stop、power-cycle、firmware）没有 provider 入口。

## 真机验证记录

2026-09-02 已在固定目标 `mentorpi` 上运行新 `rkb-3` 代码的 Linux observer canary，
`inspect/status/read` 三路均为 `AVAILABLE`。结果 artifact 记录在
[`RKB3_LANDERPI_MHS_CANARY_20260902.json`](../validation/RKB3_LANDERPI_MHS_CANARY_20260902.json)，
并绑定目标 fingerprint、manifest digest、driver digest、fact IDs 和 freshness。

## 真机边界

固定目标 `mentorpi`（`192.168.10.167/24`，网关 `192.168.10.1`）可通过已批准 SSH
profile 运行只读诊断。SSH 密码仅用于一次性登录，不写入 artifact；本阶段不修改目标机
配置、不启动执行器或任何物理写操作。本次使用的是 Rolo 自有
`rolo.mhs.linux-observer`，它只读取 procfs/sysfs 和设备节点，不代表厂商
actuator/controller driver。若目标机未提供某类真实 MHS driver，该类 canary 仍必须为
`UNAVAILABLE`，不得用静态 manifest 冒充 observed 结果。
