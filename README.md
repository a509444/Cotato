# Cotato

Cotato 是 [DeadPotato](https://github.com/lypd0/DeadPotato) 的 C++ 实现，是一个用于利用 Windows 本地提权漏洞的工具。

## 简介

Cotato 是一款利用 Windows DCOM 服务中的漏洞进行本地提权的工具。它通过利用 SeImpersonate 权限来获取 SYSTEM 权限令牌，并执行具有更高权限的进程。

## 功能特性

- 利用 DCOM 解析漏洞获取 SYSTEM 权限
- 支持执行命令行命令或直接运行可执行文件
- 提供调试模式便于问题排查
- 兼容多种 Windows 版本

## 使用方法

### 编译要求

- Visual Studio 或支持 C++11 及以上标准的编译器
- Windows SDK

### 命令行参数

```bash
Cotato.exe -c "command" | -e "exe" [args...] [-d]
```

参数说明：
- `-c, --cmd "cmd"` 通过 cmd.exe /c 运行命令
- `-e, --exe "exe"` 运行指定的可执行文件（无窗口，非交互式）
- `-d, --debug` 启用日志输出

### 示例

执行命令：
```bash
Cotato.exe -c "whoami" -d
```

运行可执行文件：
```bash
Cotato.exe -e "C:\\Windows\\System32\\cmd.exe" -d
```

## 注意事项

1. 此工具需要当前用户拥有 SeImpersonate 权限才能正常工作
2. 仅在授权的渗透测试和安全研究中使用
3. 使用前请确保已获得适当的权限和法律许可

## 工作原理

Cotato 通过以下步骤实现提权：

1. 检查当前进程是否具有 SeImpersonate 特权
2. 创建唯一的命名管道
3. 设置 DCOM 解组触发器
4. 利用漏洞获取 SYSTEM 权限令牌
5. 使用获取的令牌创建新进程

## 免责声明

⚠️ **重要免责声明** ⚠️

此工具仅供合法的安全研究、渗透测试和教育目的使用。

使用者在使用此工具时必须遵守相关法律法规，并确保已获得目标系统的合法授权。

作者不对任何非法使用此工具造成的后果承担责任。

请负责任地使用此工具，仅在授权范围内进行安全测试。

## 致谢

- 感谢 [DeadPotato](https://github.com/lypd0/DeadPotato) 项目的原始研究
- 感谢相关的安全研究人员对 Windows 提权技术的贡献

## 许可证

此项目仅供学习和研究目的使用。