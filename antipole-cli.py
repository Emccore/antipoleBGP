#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# antipoleBGP 管理命令（开发/本地入口）。
# 部署后由 deploy.sh 装成 /usr/local/bin/antipole，逻辑同一份。
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.cli import main

if __name__ == "__main__":
    main()