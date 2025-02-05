from .sdCpm import *
from .setup import *
from .api import *
import os
from aiohttp import web

static_dir_path = os.path.join(os.path.dirname(__file__), 'kaji')
if os.path.exists(static_dir_path):
    server.PromptServer.instance.app.add_routes([web.static('/kaji/', static_dir_path)])
else:
    print("Static directory not found.")


extension_dirs = [
    "js",
    "kaji/workbench",
]
# Mount web directory
WEB_DIRECTORY = f"./{extension_dirs[0]}"
WEB_DIRECTORY2 = f"./{extension_dirs[0]}"

# 这个地方会提前执行，comfyUI的8188端口还没启动。（不知道为何 bxb 是在8188进程跑起来后，才执行__init__.py）
thread_run()

NODE_CLASS_MAPPINGS = {
    "cpm_textInput": cpm_textInput,
}
NODE_DISPLAY_NAME_MAPPINGS = {"cpm_textInput": "cpm_textInput"}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY","WEB_DIRECTORY2"]
