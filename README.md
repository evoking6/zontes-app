# 升仕 Zontes App 协议文档

面向希望构建自己 App 的开发者，按两份文档整理从账号登录到远程/蓝牙控车的实际协议。包含字段来源、报文格式、算法、响应、异常处理、平台实现要点，以及可独立运行的离线示例和原始 Native 测试向量。

1. **[远端控车协议](docs/远端控车协议.md)**：登录、资料补全、Token刷新、车辆列表/切换、授权、状态/轨迹、9种TCP命令、白盒/AES/RSA、公钥版本、应答和状态同步。
2. **[蓝牙控车协议](docs/蓝牙控车协议.md)**：扫描与目标确认、GATT UUID/CCCD、准备帧、challenge、四种动作、长PKE截断、分片/通知、ACK、车辆参数和RGB设置。

分析样本为 ShiRide 1.2.25 / 1.3.0，并与已有 ZontesRide iOS 源码交叉核对。该项目为社区互操作资料，不是厂商发布的官方协议。

## 快速验证

```sh
git clone https://github.com/evoking6/zontes-app.git
cd zontes-app
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python examples/verify.py
```

Python 3.10+。示例和测试仅构造/解析内存报文，不登录账号、不连接云端或蓝牙、不操作车辆。所有账号和车辆输入均为合成测试数据。

## 配套文件

| 路径 | 内容 |
|---|---|
| [examples/protocol.py](examples/protocol.py) | 独立白盒、远程AES/RSA、蓝牙动作、分帧/保守ACK、HTTP表单、设置/RGB编码 |
| [resources/](resources/) | 解码白盒表、两版RSA公钥、表结构和指纹 |
| [vectors/](vectors/) | 两版完整远程RSA测试向量、96组蓝牙向量、白盒向量 |
| [evidence/native-verification.json](evidence/native-verification.json) | 原始ARM64离线差分范围和结果 |
| [evidence/source-index.json](evidence/source-index.json) | 样本/源文件指纹、函数定位、证据边界 |
| [tests/test_protocol.py](tests/test_protocol.py) | 向量、边界、拆包、错误关联、文档资源检查 |

2026-10-30 已离线核对新版9种命令的18条明文/18个RSA密文；96组蓝牙报文分别对照两版原始Native，共192次比较。结果一致只代表样本算法一致，**本次没有做真实账号登录或实车控车验收**。不同车型和固件仍有待确认的字段，已在文档逐项列明。

移植时先跑固定向量，再使用自己的账号获取自己的车辆材料。不要把登录名当UserCode，不要混用不同车的PKECode/MCUID；动作发出后超时表示结果未知，不能无条件重发或切通道补发。

文档、独立示例与测试使用 [MIT](LICENSE)。协议资源来源及第三方材料边界见 [NOTICE](NOTICE)。本仓库不包含APK、SO、账号凭据、真实车辆数据或私钥。
