#!/bin/bash
# antipoleBGP 部署（旧入口）。逻辑统一在根目录 install.sh（修 bad sources / GitHub 镜像 / 就地安装），
# 这里直接转发过去，避免两份逻辑冲突。
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec bash install.sh "$@"