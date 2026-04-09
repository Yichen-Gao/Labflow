# 贡献指南

感谢你愿意改进 Labflow。为保证维护效率，请先按这份指南提交。

## 适合贡献的方向

- Bug 修复（统计口径、TUI 显示、命令行为）
- 文档改进（安装步骤、排障、示例）
- 新功能（先提 Issue 讨论范围）
- 测试补充（回归测试、边界条件）

## 提交前建议流程

1. 先开 Issue（尤其是中大型改动）
2. Fork 仓库并创建分支
3. 完成改动并补测试
4. 本地通过测试后再提交 PR

## 本地开发

```bash
git clone https://github.com/Yichen-Gao/Labflow.git
cd Labflow
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

使用示例配置：

```bash
cp labflow.example.json labflow.json
```

## 运行测试

```bash
python3 -m unittest discover -s tests
```

如果改动影响命令行行为，建议至少手动验证：

```bash
PYTHONPATH=src python3 -m labflow --config labflow.example.json --help
```

## 代码风格

- 保持改动最小化，避免无关重构
- 变量和函数命名清晰、可追踪
- 不提交敏感信息（密码、授权码、内网地址）
- 不修改 `labflow.json` 这类本机私有配置

## Pull Request 要求

PR 描述请包含：

- 改了什么
- 为什么要改
- 如何验证（命令或测试）
- 是否影响部署或统计口径

建议附 1-2 条关键输出截图或日志片段，便于快速审阅。

## 文档改动

如果你改了行为或命令，请同步更新：

- `README.md`
- `docs/INSTALL.md`
- `docs/ADMIN_COMMANDS.md`

这样用户能直接按文档复现。
