# 升仕 Zontes App 协议文档

面向希望构建自己 App 的开发者，按三份文档整理账号登录、远程/蓝牙控车和行车记录仪的实际协议。包含字段来源、报文格式、算法、响应、异常处理、平台实现要点，以及可独立运行的离线示例和测试向量。

1. **[远端控车协议](docs/远端控车协议.md)**：登录、资料补全、Token刷新、车辆列表/切换、授权、状态/轨迹、9种TCP命令、白盒/AES/RSA、公钥版本、应答和状态同步。
2. **[蓝牙控车协议](docs/蓝牙控车协议.md)**：扫描与目标确认、GATT UUID/CCCD、准备帧、challenge、四种动作、长PKE截断、分片/通知、ACK、车辆参数和RGB设置。
3. **[行车记录仪协议](docs/行车记录仪协议.md)**：基于703T固件的Wi-Fi接入、HTTP日期/录像列表、分页、媒体地址修复、播放/下载、Range局限、平台接入和排错；不包含实时画面实现。

分析样本为 ShiRide 1.2.25 / 1.3.0，并与已有 ZontesRide iOS 源码交叉核对。该项目为社区互操作资料，不是厂商发布的官方协议。

2026-10-30 联调更正：**Native 输出与当前线上可用传输不能画等号。** Mac 实测两版 RSA 认证包均无响应；ASCII `*UL,...#` 收到 `*BR,1#`。只读刷新仅返回不含命令/车辆身份的 `,OK#`；一次寻车已提交但未获得完整车辆确认，实车执行仍待验收。见[脱敏联调记录](evidence/wire-verification.json)。此前将 256 字节 RSA 包直接描述为可用线上路径的结论撤回。

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
| [examples/protocol.py](examples/protocol.py) | 独立白盒、远程AES/RSA、蓝牙动作、分帧/保守ACK、HTTP表单、设置/RGB编码 |
| [examples/dashcam.py](examples/dashcam.py) | 记录仪只读JSON构造、日期/录像响应解析、无协议头URL规范化，无网络操作 |
| [resources/](resources/) | 解码白盒表、两版RSA公钥、表结构和指纹 |
| [vectors/](vectors/) | 两版完整远程RSA测试向量、96组蓝牙向量、白盒向量 |
| [evidence/native-verification.json](evidence/native-verification.json) | 原始ARM64离线差分范围和结果 |
| [evidence/source-index.json](evidence/source-index.json) | 样本/源文件指纹、函数定位、证据边界 |
| [evidence/dashcam-verification.json](evidence/dashcam-verification.json) | DVR固件指纹、字段/分页/媒体函数定位、模拟播放与实车验收边界 |
| [vectors/dashcam.json](vectors/dashcam.json) | 合成日期、列表、媒体/缩略图URL样例 |
| [tests/test_protocol.py](tests/test_protocol.py) | 向量、边界、拆包、错误关联、文档资源检查 |

2026-10-30 已离线核对新版9种命令的18条明文/18个RSA密文；96组蓝牙报文分别对照两版原始Native，共192次比较。后续使用已授权账号完成官方登录、资料和车辆读取及有限 TCP 联调；**车辆实际动作尚未验收**。`build_packets()` 保留为离线 Native RSA 示例，`build_text_frames()` 是已验证认证、尚待车辆动作验收的文本传输候选。不同车型和固件仍有待确认的字段，已在文档逐项列明。

移植时先跑固定向量，再使用自己的账号获取自己的车辆材料。不要把登录名当UserCode，不要混用不同车的PKECode/MCUID；动作发出后超时表示结果未知，不能无条件重发或切通道补发。

行车记录仪资料直接对照 `JC_703T25_V02.26.02.02.60` 的 DVR 程序与配置。用户反馈已能取到实车文件列表；Mac 已对合成 H264 文件完成 HTTP 回放解码，**真实车机录像播放/下载仍待验收**。固件的 Range 发送存在已静态核对的局限，不能把本地模拟播放通过等同于车机兼容性通过。

文档、独立示例与测试使用 [MIT](LICENSE)。协议资源来源及第三方材料边界见 [NOTICE](NOTICE)。本仓库不包含APK、SO、账号凭据、真实车辆数据或私钥。
