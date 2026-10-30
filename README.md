# 升仕 Zontes App 协议文档

面向希望构建自己 App 的开发者，按三份文档整理账号登录、远程/蓝牙控车和行车记录仪的实际协议。包含字段来源、报文格式、算法、响应、异常处理、平台实现要点，以及可独立运行的离线示例和测试向量。

1. **[远端控车协议](docs/远端控车协议.md)**：登录、资料补全、Token刷新、车辆列表/切换、授权、状态/轨迹、当前原厂样本、已确认 API 入口、1.59 签名、四套 CBC 参数、UTDID 包装、认证和回执边界。
2. **[蓝牙控车协议](docs/蓝牙控车协议.md)**：扫描与目标确认、GATT UUID/CCCD、准备帧、challenge、四种动作、长PKE截断、分片/通知、ACK、车辆参数和RGB设置。
3. **[行车记录仪协议](docs/行车记录仪协议.md)**：基于703T固件的Wi-Fi接入、HTTP日期/录像列表、分页、媒体地址修复、播放/下载、Range局限、平台接入和排错；不包含实时画面实现。

远程控车现以官方 Android **1.59 / 4825** 为唯一分析基准。旧 ShiRide 样本、旧文本兼容通道及旧 RSA 密钥已退出当前远控实现依据，旧说明已[归档](docs/history/远端控车协议-旧样本.md)。该项目为社区互操作资料，不是厂商发布的官方协议。

**1.59 的 TCP 认证封装和签名只读刷新已验证；mPaaS 登录在 Mac 已验证，iOS 登录 400 尚待移植修复，物理控车仍待车主验收。** 新实现使用 AES-CBC/Base64 与设备标签；旧 RSA/文本兼容通道不用于当前实现。本轮仅登录和读取，未发送车辆动作。证据见[远端控车协议](docs/远端控车协议.md)和[分析记录](evidence/official-1.59-analysis.json)。

## 快速验证

```sh
git clone https://github.com/evoking6/zontes-app.git
cd zontes-app
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python examples/verify.py
```

Python 3.10+。示例和测试仅构造/解析内存报文，不登录账号、不连接云端、蓝牙或车机HTTP，不操作车辆。所有账号、车辆和录像输入均为合成测试数据。文档中的 `curl` 只在读者手动执行时连接自己的车机。

## 配套文件

| 路径 | 内容 |
|---|---|
| [examples/remote159.py](examples/remote159.py) | 当前 1.59 签名和四套 CBC/设备标签封装，纯离线 |
| [resources/remote-159.json](resources/remote-159.json) | APK 恢复并验证的 AES 参数 |
| [vectors/remote-159.json](vectors/remote-159.json) | 合成认证/只读请求逐字节向量 |
| [examples/protocol.py](examples/protocol.py) | 独立白盒、蓝牙动作、分帧/保守ACK、HTTP表单、设置/RGB；远程 AES/RSA 部分仅为历史离线样例 |
| [examples/dashcam.py](examples/dashcam.py) | 记录仪只读JSON构造、日期/录像响应解析、无协议头URL规范化，无网络操作 |
| [resources/](resources/) | 解码白盒表、历史样本 RSA 公钥、表结构和指纹；历史密钥不用于 1.59 |
| [vectors/](vectors/) | 历史远程 RSA 向量、96组蓝牙向量、白盒向量 |
| [evidence/native-verification.json](evidence/native-verification.json) | 原始ARM64离线差分范围和结果 |
| [evidence/source-index.json](evidence/source-index.json) | 样本/源文件指纹、函数定位、证据边界 |
| [evidence/dashcam-verification.json](evidence/dashcam-verification.json) | DVR固件指纹、字段/分页/媒体函数定位、模拟播放与实车验收边界 |
| [vectors/dashcam.json](vectors/dashcam.json) | 合成日期、列表、媒体/缩略图URL样例 |
| [tests/test_protocol.py](tests/test_protocol.py) | 向量、边界、拆包、错误关联、文档资源检查 |

`examples/remote159.py` 是当前远控入口。`examples/protocol.py` 中的 `build_packets()`、`build_text_frames()` 仅供历史分析，不用于当前远控。测试同时覆盖当前签名/封装以及历史字节、蓝牙、DVR 回归；离线测试通过不能替代实车动作验收。

行车记录仪资料直接对照 `JC_703T25_V02.26.02.02.60` 的 DVR 程序与配置。用户反馈已能取到实车文件列表；Mac 已对合成 H264 文件完成 HTTP 回放解码，**真实车机录像播放/下载仍待验收**。固件的 Range 发送存在已静态核对的局限，不能把本地模拟播放通过等同于车机兼容性通过。

文档、独立示例与测试使用 [MIT](LICENSE)。协议资源来源及第三方材料边界见 [NOTICE](NOTICE)。本仓库不包含APK、SO、账号凭据、真实车辆数据或私钥。
