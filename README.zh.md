# secbrief

[English](README.md) | [한국어](README.ko.md) | **中文** | [日本語](README.ja.md)

**面向AI代理管理机器的每日漏洞简报。**

你对AI代理说"帮我盯着自己机器的漏洞"。代理会安装这个工具。之后每隔几小时，机器生成的简报会告诉你"什么变了""哪里需要你做判断"。LLM不做任何决定——它只负责解释。

```bash
git clone <本仓库> && cd secbrief
python3 secbrief.py init        # 生成config.json
$EDITOR config.json             # 填写SSH主机 / python环境 / brew监视列表
python3 secbrief.py run --baseline   # 首次运行：建立基线（无警报）
python3 secbrief.py run              # 之后由cron/launchd每6小时运行一次，只对差异报警
python3 secbrief.py doctor           # 扫描器还活着吗？上次成功是什么时候？
```

安装约5分钟。不需要API密钥、账号或代理框架。

## 它做什么

**数据源（免费·官方·无需密钥）：**
- [OSV.dev](https://osv.dev) querybatch＋advisory详情——与实际安装的版本对照（PyPI用purl，Ubuntu/Debian用`pkg:deb/<distro>/...`）。系统包以发行版的advisory为准，因此backport版本（如`1.1.0-2build2.1`）不会被上游版本比较误判。
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)——正在被实际利用的漏洞会被升级。即使你之前"接受（accepted）"了某项，只要其CVE日后进入KEV，就会**自动解除接受**。
- [formulae.brew.sh](https://formulae.brew.sh)——Homebrew没有CVE数据库，因此formula的版本差异会作为独立板块（更新迟缓）报告，不会伪装成CVE。

**清单（只读。不对你的机器做任何更改）：**
- Python环境：`pip list`（你指定的任意解释器）
- Ubuntu/Debian主机：通过SSH的`dpkg-query`（密钥认证）
- macOS Homebrew：对监视列表执行`brew list --versions`

**简报**（markdown·每次运行一个文件）把所有内容分为四类：

- `[要対応]`——修复已发布且CVE在KEV中。今天就行动。
- `[要対応（緩和）]`——正在被利用但修复未提供。先缓解（切断输入路径）。
- `[推奨]`——修复已发布·不在KEV中。按你自己的节奏打补丁。
- `[観察]`——修复未提供·未被利用。持续观察。（故意不标注严重度数值：对无法打补丁的漏洞给出CVSS分数是噪音，不是信号。）
- 另外还有机器可以证明无关的`[不要]`行、你确认后接受的`[（accepted）]`行，以及brew版本差异板块。

每条发现都带有机器验证过的四元组（advisory ID·安装版本·修复版本·KEV标记）以及指向该advisory的链接。

## 支撑可信度的规则

1. **对照由确定性代码完成，不使用LLM。** 版本比较是幻觉会造成真实伤害的地方，所以绝不交给模型。
2. **输出门。** 缺少advisory ID·安装版本·修复状态·KEV标记的行无法输出——无法验证的主张会被丢弃并计数。从结构上杜绝捏造发现。
3. **advisory正文是数据而非指令。** 写着"运行这个命令"的CVE描述只会被当作文本引用。负责解释工序的`PROMPT.md`也向LLM传达同样的约束。
4. **水印只在全部数据源成功时推进。** 一次失败的抓取如果推进了差分状态，未来的CVE就会被永久隐藏。降级运行改为发出`点检失败`警报。静默死掉的扫描器看起来像安全——这个扫描器拒绝沉默。
5. **首次运行是基线。** 从干净状态开始，而不是200条警报。
6. **"没有输入路径"永远不由机器决定。** 只有你能登记`ignore_overrides`。（机器可以证明的两种机械情况——发行版已修复·未安装——是另一回事。）

## 两种用法

- **路线A（由LLM解释）：** 用cron运行secbrief。警报文件更新后，打开`briefing.md`——或者用`python3 secbrief.py paste`生成包含PROMPT.md＋简报的单个文件，粘进任意LLM对话，让它给出通俗解释和按优先级排列的计划。
- **路线B（由代理维护）：** 把`AGENTS.md`交给你的编码代理。它可以安装、排程、验证健康状态、起草补丁命令。它仍然不会无人值守地应用补丁——你说"做吧"，然后自己执行。

## 排程

每6小时是良好的默认值（12/24小时也可以）。launchd的plist和cron行的例子在`docs/scheduling.md`。健康检查用`secbrief.py doctor`——如果简报文件的mtime超过你的周期两倍，说明调度任务已经死亡。

## 诚实的局限

- 设计上不监视的内容（每季度复查）：容器镜像、浏览器、EOL运行时、snap/flatpak、全局npm包。每次简报的页眉都会列出它们，让"没在看"永远不会被遗忘。
- **OSV querybatch在每次查询1000条处截断。** 超过这个数量的源（典型是Linux内核），API返回的子集是不确定的，所以secbrief拒绝枚举。这些源会被压缩为一行，用发行版自身的待升级状态（有apt候选＝有修复）判定，并在页眉列出名称（`OSV 1000-cap`）。对它们无法做CVE级别的KEV升级——但应对动作（执行发行版升级）不变。
- 数据源滞后：OSV很快（通常24小时内）但不是即时的。CISA KEV目录按美国政府的时间表更新。
- 简报告诉你"什么需要修"，而不是"如何安全地修你的特定应用"。修复版本是机器验证过的；回滚计划不是。
- 这是简报工具，不是扫描器产品：它只把包清单与advisory对照。它看不到运行时暴露（哪个服务真正解析不受信任的输入）——那个判断留给你。
- 可读性：`[要対応]`保留advisory粒度的行。庞大的`[推奨]`/`[観察]`积压按（包×修复状态）压缩，advisory ID全部保留在行内。因为一次`apt upgrade`就能批量解决。

## 安全性说明

参见`SECURITY.md`（这个工具做什么、刻意不做什么，以及报告政策）。不要把机密放进`config.json`。`.gitignore`从一开始就排除了`config.json`、`state/`、`cache/`、`alerts/`。

## 贡献者

- **tenhkspark** — DGX Spark集群的所有者·运营者
- **GLM-5.3-Flash** — 设计·实现·本文档（集群上本地运行）
- **Qwen3.8-Flash-Next** — 独立安全审查（同·本地运行）
- **Nemotron 3.5 Lightning 30B-A3B** — 独立安全审查（同·本地运行）
- 其他DGX Spark集群上的本地LLM — 评审与验证

所有AI贡献者均在所有者的硬件上本地运行，未使用任何外部AI服务。

## 许可证

MIT。数据在运行时从公开来源获取（OSV.dev为CC-BY-4.0，KEV为美国政府公共领域）。secbrief本身不重新分发任何数据。
