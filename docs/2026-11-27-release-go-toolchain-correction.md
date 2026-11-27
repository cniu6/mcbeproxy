# 发布工作流的 Go 工具链：一次更正

日期：2026-11-27
涉及：`.github/workflows/release.yml`，提交 `51a6be8`

## 更正

提交 `51a6be8` 的说明写着“让 CI 的版本跟随 go.mod”，并暗示发布使用 `go1.26.8`。这一说法不准确，
依据以下对 `actions/setup-go`（v5 标签）源码与 Go 命令源码的核实。具体位置：setup-go 的 `src/installer.ts` 中 `parseGoVersionFile` 函数（约第 498 行）。

## 实际行为

1. `setup-go` 解析 `go-version-file: go.mod` 时，只用 `/^go (\d+(\.\d+)*)/m` 匹配 `go` 指令，
   **不读取 `toolchain` 指令**。对当前的 `go.mod` 解析结果是 `1.26.0`，安装的也是 `1.26.0`。
2. `setup-go` 的输入中**没有任何参数**可以直接指定 toolchain 版本；它的版本输入只有
   `go-version`（语义版本）和 `go-version-file`（仅读取 `go` 指令）。
3. Go 命令在默认的 `GOTOOLCHAIN=auto` 下读取 `toolchain` 指令，发现它比已安装的版本新，
   于是**在构建时下载并切换到 `go1.26.8`**。因此最终二进制由 `go1.26.8` 编译，但依赖一次网络下载，
   而不是由 `setup-go` 安装。

## 未解决的选择

要让发布不依赖构建时下载，唯一的办法是把 `go-version` 显式写成 `'1.26.8'`。该值是合法的 `x.y.z` 格式。
这个改动会改变发布所用的工具链，尚未实施，需要在 CI 中验证后再决定。

## 尚未验证

- 本机无法获得 `go1.26.8`（禁止下载时报 `toolchain not available`），因此没有在本机复现构建。
- CI 中实际的下载行为与发布结果，尚未在 GitHub Actions 中运行验证。
