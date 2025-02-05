import os
import time
import base64
from PIL import Image
import aiohttp
from aiohttp import web
import server
import json
import sys
import re
import uuid
import hashlib
import threading
import asyncio
import websockets
from comfy.cli_args import parser
import logging
import random
import mimetypes
import math
import platform
import subprocess
from datetime import datetime
import folder_paths
from pathlib import Path

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)


DEBUG = True
BASE_URL = "https://env-00jxh693vso2.dev-hz.cloudbasefunction.cn"

UPLOAD_OSS_URL = "/http/ext-storage-co/getUploadFileOptions"
END_POINT_URL3 = "/kaji-upload-file/uploadFile" 
END_POINT_URL1 = "/kaji-upload-file/uploadProduct"  
OSS_DOMAIN = "https://kajiai.cn/"
END_POINT_URL2 = "/get-ws-address/getWsAddress"
END_POINT_URL_FOR_PRODUCT_1 = "/plugin/getProducts"
END_POINT_URL_FOR_PRODUCT_2 = "/plugin/createOrUpdateProduct"
END_POINT_URL_FOR_PRODUCT_3 = "/plugin/deleteProduct"
END_POINT_URL_FOR_PRODUCT_4 = "/plugin/toggleAuthorStatus"
END_POINT_URL_FOR_PRODUCT_5 = "/plugin/toggleDistributionStatus"
END_POINT_FILE_IS_EXITS = "/plugin/fileIsExits"
END_POINT_DELETE_FILE = "/plugin/deleteFiles"
END_POINT_GET_WORKFLOW = "/plugin/getWorkflow"
END_POINT_DELETE_WORKFLOW = "/plugin/deleteWorkflowFile"

media_save_dir = folder_paths.get_input_directory()
media_output_dir = folder_paths.get_output_directory()

print(f"输入目录：{media_save_dir}")
print(f"输出目录：{media_output_dir}")


wss_c1 = None
wss_c2 = None
last_value = None
last_time = None
RECONNECT_DELAY = 5
MAX_RECONNECT_ATTEMPTS = 10
HEART_INTERVAL = 30
gc_task_queue = asyncio.Queue()  

taskIdDict = dict()
listeningTasks = set()  
numberDict = dict()
runningNumber = -1  
queue_size = 0  


def parse_args():
    args = parser.parse_args()
    return args if args.listen else parser.parse_args([])


def get_address_from_args(args):
    return args.listen if args.listen != "0.0.0.0" else "127.0.0.1"


def parse_port_from_args(args):
    return args.port


def get_mac_address() -> str:
    mac_uid = uuid.getnode()
    mac_address = ":".join(("%012X" % mac_uid)[i : i + 2] for i in range(0, 12, 2))
    return mac_address


def get_port_from_cmd(default_port=8188):
    port = None

    def extract_port_from_arg(arg):
        match = re.search(r"--port[=\s]*(\d+)", arg)
        if match:
            return int(match.group(1))
        return None

    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except ValueError:
                continue

        extracted_port = extract_port_from_arg(arg)
        if extracted_port:
            port = extracted_port
        if port:
            break

    return port if port else default_port


def get_machine_unique_id():
    # 获取机器唯一标识符（跨平台适配）
    try:
        system = platform.system()

        if system == "Linux":
            # 优先尝试从 /etc/machine-id 获取
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    return f.read().strip()

            # 如果 /etc/machine-id 不存在，尝试 dmidecode
            try:
                result = subprocess.check_output(
                    ["dmidecode", "-s", "system-uuid"], stderr=subprocess.DEVNULL
                )
                return result.decode().strip()
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

            # 如果 dmidecode 不可用，尝试从 /proc/cpuinfo 获取 CPU 信息
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    for line in cpuinfo.split("\n"):
                        if line.startswith("Serial"):
                            return line.split(":")[1].strip()
            except FileNotFoundError:
                pass

            # 最后尝试生成基于网络接口的 UUID
            mac_address = uuid.getnode()
            return uuid.UUID(int=mac_address).hex

        elif system == "Darwin": 
            result = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
            )
            for line in result.decode().split("\n"):
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
            raise ValueError("IOPlatformUUID not found")

        elif system == "Windows": 
            result = subprocess.check_output(["wmic", "csproduct", "get", "UUID"])
            return result.decode().split("\n")[1].strip()

        else:
            raise ValueError("Unsupported platform")

    except Exception as e:
        raise RuntimeError(f"Failed to retrieve machine ID: {e}")


def generate_unique_hash():
    # 考虑到端口动态性和mac地址如果在虚拟机中更改mac，或者更换网卡也会受影响，使用机器唯一标识符生成稳定的哈希值
    machine_id = get_machine_unique_id()
    hash_value = hashlib.sha256(machine_id.encode()).hexdigest()
    return hash_value


args = parse_args()
cur_client_id = f"{str(uuid.uuid4())}:{parse_port_from_args(args)}"
cfy_ws_url = "ws://{}:{}/ws?clientId={}".format(
    get_address_from_args(args), parse_port_from_args(args), cur_client_id
)

uni_hash = generate_unique_hash()
print(f"每次启动都是相同的机器码，uni_hash：{uni_hash}")


def get_comfyui_address():
    args = parse_args()
    address = get_address_from_args(args)
    port = parse_port_from_args(args)
    return f"http://{address}:{port}"


def getInputTypeArr(data):

    input_type_arr = []
    for key, item in data.items():
        if item.get("class_type") == "sdCpm":
            inputs = item.get("inputs")
            input_text1 = inputs.get("input_text1(optional)")
            input_text2 = inputs.get("input_text2(optional)")
            input_text3 = inputs.get("input_text3(optional)")
            input_img1 = inputs.get("input_img1(optional)")
            input_img2 = inputs.get("input_img2(optional)")
            input_img3 = inputs.get("input_img3(optional)")
            input_video1 = inputs.get("input_video1(optional)")
            input_video2 = inputs.get("input_video2(optional)")
            input_video3 = inputs.get("input_video3(optional)")

            text1_tips = inputs.get("text1_tips")
            text2_tips = inputs.get("text2_tips")
            text3_tips = inputs.get("text3_tips")
            img1_tips = inputs.get("img1_tips")
            img2_tips = inputs.get("img2_tips")
            img3_tips = inputs.get("img3_tips")
            video1_tips = inputs.get("video1_tips")
            video2_tips = inputs.get("video2_tips")
            video3_tips = inputs.get("video3_tips")

            if input_text1:
                text1 = {
                    "index": input_text1[0],
                    "class_type": data.get(input_text1[0], {}).get("class_type"),
                    "input_des": text1_tips,
                }
                input_type_arr.append(text1)
            if input_text2:
                text2 = {
                    "index": input_text2[0],
                    "class_type": data.get(input_text2[0], {}).get("class_type"),
                    "input_des": text2_tips,
                }
                input_type_arr.append(text2)
            if input_text3:
                text3 = {
                    "index": input_text3[0],
                    "class_type": data.get(input_text3[0], {}).get("class_type"),
                    "input_des": text3_tips,
                }
                input_type_arr.append(text3)
            if input_img1:
                img1 = {
                    "index": input_img1[0],
                    "class_type": data.get(input_img1[0], {}).get("class_type"),
                    "input_des": img1_tips,
                }
                input_type_arr.append(img1)
            if input_img2:
                img2 = {
                    "index": input_img2[0],
                    "class_type": data.get(input_img2[0], {}).get("class_type"),
                    "input_des": img2_tips,
                }
                input_type_arr.append(img2)
            if input_img3:
                img3 = {
                    "index": input_img3[0],
                    "class_type": data.get(input_img3[0], {}).get("class_type"),
                    "input_des": img3_tips,
                }
                input_type_arr.append(img3)
            if input_video1:
                video1 = {
                    "index": input_video1[0],
                    "class_type": data.get(input_video1[0], {}).get("class_type"),
                    "input_des": video1_tips,
                }
                input_type_arr.append(video1)
            if input_video2:
                video2 = {
                    "index": input_video2[0],
                    "class_type": data.get(input_video2[0], {}).get("class_type"),
                    "input_des": video2_tips,
                }
                input_type_arr.append(video2)
            if input_video3:
                video3 = {
                    "index": input_video3[0],
                    "class_type": data.get(input_video3[0], {}).get("class_type"),
                    "input_des": video3_tips,
                }
                input_type_arr.append(video3)
    logging.info(f"input_type_arr =====》 {input_type_arr}")
    return input_type_arr


def reformat(uploadData):
    # 从数据中提取必要字段
    uniqueid = uploadData.get("uniqueid")
    workflow = uploadData.get("workflow")
    output = uploadData.get("output")
    formMetaData = uploadData.get("formMetaData")

    if not uniqueid or not workflow or not output:
        raise ValueError("缺少必要字段：uniqueid, workflow 或 output")

    # 确保 formMetaData 是字典类型
    if not isinstance(formMetaData, dict):
        raise TypeError("formMetaData 必须是一个字典对象")

    images = uploadData.get("images", [])
    # 替换上传数据中的 media_urls
    uploadData["media_urls"] = images

    # 添加额外数据
    uploadData["uni_hash"] = uni_hash
    uploadData["formMetaData"] = formMetaData

    # 移除工作流不上传
    uploadData.pop("output", None)
    uploadData.pop("workflow", None)

    return uploadData


# 插件端与服务器端的心跳。理论上，初始化一次，任务变动（新增+1、完成-1）时触发一次。就可以。 其余时刻发送（数据都是重复）是多余的（网络探活不靠这个）
async def send_heartbeat(websocket):
    while True:
        try:
            # 获取所有工作流id
            workflow_path = find_plugin_root() + "config/pipeline"
            uniqueids = get_filenames(workflow_path)

            payload = {
                "type": "ping",
                "data": {
                    "uni_hash": uni_hash,
                    "uniqueids": uniqueids,
                },
            }
            print(f"发送心跳； ping 数据为：{payload}")

            heartbeat_message = json.dumps(payload)
            await websocket.send(heartbeat_message)
        except websockets.ConnectionClosedError:
            print("发送ping失败, WebSocket连接意外关闭，可能网络出现问题")
            raise e
        except Exception as e:
            print(f"发送ping失败: {e}")
            raise e

        await asyncio.sleep(HEART_INTERVAL)


def get_filenames(directory):
    if os.path.exists(directory):
        all_entries = os.listdir(directory)
        # 过滤掉隐藏文件和非文件
        all_entries = [
            name
            for name in all_entries
            if os.path.isfile(os.path.join(directory, name))
            and not name.startswith(".")
        ]
        # 提取文件名（去掉扩展名）
        all_entries = [name.split(".")[0] for name in all_entries]
        return all_entries
    else:
        return []


async def receive_messages(websocket, c_flag):
    while True:
        try:
            message = await websocket.recv()
        except Exception as e:
            # WebSocket 连接出问题，抛出异常供上游处理
            logger.critical(f"咔叽ws{c_flag} 接收消息失败，可能需要重连: {e}")
            raise e

        try:
            if c_flag == 1:
                logger.info(f"接收支付宝云端ws事件数据: {message}")
                await process_server_message1(message)
            elif c_flag == 2:
                # logger.info(f"接收comfyUI的当前生图任务状态: {message}")
                await process_server_message2(message)
            else:
                logger.warning(f"未识别的c_flag: {c_flag}, 丢弃消息: {message}")
        except Exception as e:
            # 消息处理异常，记录错误但不中断循环
            logger.error(f"处理消息时发生错误 (c_flag={c_flag}): {e}")


async def handle_websocket(c_flag):
    global wss_c1, wss_c2
    while True:
        try:
            if c_flag == 1:
                url = await get_wss_server_url()
            elif c_flag == 2:
                url = cfy_ws_url
            else:
                return

            logging.info(f"咔叽ws{c_flag},url: {url},开始发起连接")
            async with websockets.connect(url) as websocket:
                print(f"咔叽ws{c_flag} 连接成功！~")
                if c_flag == 1:
                    wss_c1 = websocket
                    tasks = [
                        # 显示任务调度
                        asyncio.create_task(send_heartbeat(websocket)),
                        asyncio.create_task(receive_messages(websocket, c_flag)),
                    ]
                elif c_flag == 2:
                    wss_c2 = websocket
                    tasks = [
                        asyncio.create_task(receive_messages(websocket, c_flag)),
                    ]
                # 等待上面的所有任务完成（除非某个任务抛错，也就是websocket连接失败，否则永久循环）
                await asyncio.gather(*tasks)
        except (websockets.ConnectionClosedOK, websockets.ConnectionClosedError) as e:
            print(f"咔叽ws{c_flag} 连接不上{e}")
        except Exception as e:
            print(f"咔叽ws{c_flag} 连接失败,请检查网络{e}")

        await asyncio.sleep(RECONNECT_DELAY)


# 咔叽服务端的数据
async def process_server_message1(message):
    try:
        # 尝试将接收到的消息解析为 JSON 对象
        message_data = json.loads(message)
        message_type = message_data.get("type")
        data = message_data.get("data", {})

        if message_type == "generate_submit":
            print("收到生图消息", data)
            await deal_recv_generate_data(data)

        elif message_type == "cancel_listen":
            print("任务进度监听取消", data)
            listeningTasks.discard(data["kaji_generate_record_id"])

    except json.JSONDecodeError:
        print("Received non-JSON message from server.")
    except Exception as e:
        print(f"An error occurred while processing the message: {e}")


# comfyUI websocket 实时返回的任务数据事件
async def process_server_message2(message):
    global last_value, last_time, runningNumber, queue_size
    message_json = json.loads(message)
    message_type = message_json.get("type")
    if message_type == "status":
        # 三种时刻触发该事件(新增任务，开始任务，完成任务)，通过该事件得知机器的实时繁忙程度，用于负载均衡（queue_remaining:队列大小）

        # 1:每次生成提交成功时，回调给服务端的时候，能立即感知到队列大小，负载均衡也就比较准
        # 2:此处记入内存的值，可以在未来某个事件一并带到服务端
        status_data = message_json.get("data", {})
        queue_size = status_data.get("status").get("exec_info").get("queue_remaining")
    elif message_type == "execution_start":
        # 任务开始
        prompt_id = message_json["data"]["prompt_id"]
        kaji_generate_record_id = taskIdDict.get(prompt_id)
        runningNumber = numberDict.pop(prompt_id)

        # 需要通知的所有任务主键
        result = []
        for prompt_id in numberDict.keys():
            if prompt_id in taskIdDict:
                id = taskIdDict[prompt_id]
                if id in listeningTasks:
                    result.append(id)
        print(result)

        startEvent = {
            "type": "execution_start",
            "data": {
                "kaji_generate_record_id": kaji_generate_record_id,
                "prompt_id": prompt_id,
                "runningNumber": runningNumber,
                "ids": result,
            },
        }
        await wss_c1.send(json.dumps(startEvent))
        print(f"新任务开始，成功发给服务端: {startEvent}")
    elif message_type == "execution_cached":
        # 该任务被缓存好的所有节点数组（服务端暂时不用，不用通知）
        pass
    elif message_type == "executing":
        # 该任务某个节点正在执行中（服务端暂时不用，不用通知）
        data = message_json.get("data", {})
        logger.info(f"executing事件: {data}")
        prompt_id = data.get("prompt_id")

        node = data.get("node")
        if node is None:
            # 源码查看显示，这里才是任务真正结束的时候
            runningNumber = -1
            # 发送机器的队列大小的变化
            queueChangeEvent = {
                "type": "update_queue",
                "data": {"uni_hash": uni_hash, "queue_size": queue_size},
            }
            await wss_c1.send(json.dumps(queueChangeEvent)) 
            print(f"上个任务完成了，总队列大小发给服务端: {queueChangeEvent}")
    elif message_type == "progress":
        # 某个节点的具体的执行进度，与executing事件对应
        # （整个工作流往往最耗时的节点是ksample那个节点，此处的步长数据就当作工作流的进度）
        progress_data = message_json.get("data", {})
        prompt_id = progress_data.get("prompt_id")

        kaji_generate_record_id = taskIdDict.get(prompt_id)
        # 判断用户是否取消监听
        if not kaji_generate_record_id in listeningTasks:
            return

        value = progress_data.get("value")
        max_value = progress_data.get("max")

        current_time = time.time() 
        # 计算剩余时间
        if last_value is not None and last_time is not None:
            # 计算时间间隔
            time_interval = current_time - last_time
            # 计算进度变化
            value_change = value - last_value

            if value_change > 0:  
                # 估算总时间
                estimated_total_time = (max_value / value_change) * time_interval
                remaining_time = estimated_total_time - (value * time_interval)
            else:
                 # 如果没有进度变化，设置剩余时间为 0
                remaining_time = 0 
        else:
            # 第一次接收进度时，无法计算剩余时间
            remaining_time = 0  
        remaining_time = math.ceil(max(remaining_time, 0))
        # 更新上一个值和时间
        last_value = value
        last_time = current_time

        progressEvent = {
            "type": "progress_update",
            "data": {
                "kaji_generate_record_id": kaji_generate_record_id,
                "prompt_id": prompt_id,
                "remaining_time": remaining_time,  
                "value": value,
                "max_value": max_value,
            },
        }
        await wss_c1.send(json.dumps(progressEvent))  
        # print(f"发送进度更新: {progressEvent}")

    elif message_type == "executed":
        pass

    elif message_type == "execution_success":
        prompt_id = message_json["data"]["prompt_id"]
        kaji_generate_record_id = taskIdDict.pop(prompt_id)
        # 通过history拿结果
        cur_history_info = await get_history_from_comfyui(prompt_id)
        # 上传所有结果,获取对应的链接
        gif_links,image_links = await upload_single_node_output_image(cur_history_info,prompt_id)
        print(f"任务完成上传gif的链接: {gif_links}")
        print(f"任务完成上传image的链接: {image_links}")
        # 所有节点完成，该任务也完成。 todo
        executionEvent = {
            "type": "execution_success",
            "data": {
                "kaji_generate_record_id": kaji_generate_record_id,
                "prompt_id": prompt_id,
                "media_data":{
                    "gifs":gif_links,
                    "images":image_links
                }
            },
        }
        await wss_c1.send(json.dumps(executionEvent))
        print(f"任务完成成功发给服务端: {executionEvent}")
        listeningTasks.discard(kaji_generate_record_id)

        pass
    elif message_type == "execution_error" or message_type == "execution_interrupted":
        print(f"执行错误: {message_json}")
        # 该任务出错了。服务端就直接失败退款
        prompt_id = message_json["data"]["prompt_id"]
        kaji_generate_record_id = taskIdDict.pop(prompt_id)

        errorEvent = {
            "type": "execution_error",
            "data": {
                "kaji_generate_record_id": kaji_generate_record_id,
                "prompt_id": prompt_id,
            },
        }
        await wss_c1.send(json.dumps(errorEvent))
        print(f"结果（错误）成功发给服务端: {errorEvent}")

        listeningTasks.discard(kaji_generate_record_id)


async def upload_single_node_output_image(cur_history_info,prompt_id):
    gif_tasks = []
    image_tasks = []
    # 获取特定 prompt_id 对应的 outputs
    history_entry = cur_history_info.get(prompt_id)
    if not history_entry or "outputs" not in history_entry:
        raise ValueError(f"No outputs found for prompt_id: {prompt_id}")

    outputs = history_entry["outputs"]

    for output_value in outputs.values():
        if "gifs" in output_value:
            for gif_info in output_value["gifs"]:
                if gif_info.get("type") != "temp":
                    filename = gif_info["filename"]
                    task = upload_output_gifs(filename)
                    gif_tasks.append(task)

        if "images" in output_value:
            for image_info in output_value["images"]:
                if image_info.get("type") != "temp":
                    filename = image_info["filename"]
                    task = upload_output_image(filename)
                    image_tasks.append(task)

    # 并发执行所有上传任务
    gif_links, image_links = await asyncio.gather(
        asyncio.gather(*gif_tasks),
        asyncio.gather(*image_tasks)
    )

    return list(gif_links), list(image_links)

async def get_wss_server_url():
    async with aiohttp.ClientSession() as session:
        # 告知服务器，有一台新机器，使用了咔叽插件，并与您网络接通中（信息放到机器表中）
        payload = {"uni_hash": uni_hash}
        async with session.post(BASE_URL + END_POINT_URL2, json=payload) as response:
            try:
                res = await response.json()
                wss_server_url = res.get("data")
                if not wss_server_url:
                    raise Exception("Failed to retrieve WebSocket server URL")
                return wss_server_url
            except json.JSONDecodeError:
                return web.Response(
                    status=response.status, text="Invalid JSON response2"
                )


@server.PromptServer.instance.routes.post(END_POINT_URL_FOR_PRODUCT_1)
async def getProducts(req):
    try:
        body = await req.json()
        token = body.get("token")

        if not token:
            return web.json_response({"error": "Token is required"}, status=400)

        jsonData = {
            "token": token,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                BASE_URL + END_POINT_URL_FOR_PRODUCT_1, json=jsonData
            ) as response:
                res_js = await response.json()

                return web.json_response(res_js)

    except Exception as e:
        print("Error parsing request body:", e)
        return web.json_response({"error": "Invalid request body"}, status=400)


@server.PromptServer.instance.routes.post(END_POINT_URL_FOR_PRODUCT_3)
async def deleteProduct(req):
    jsonData = await req.json()

    async with aiohttp.ClientSession() as session:
        # jsonData["product_id"] = "xxxx"  # 写死
        async with session.post(
            BASE_URL + END_POINT_URL_FOR_PRODUCT_3, json=jsonData
        ) as response:
            res_js = await response.json()
            data = res_js.get("data", {})
            print("res_js", res_js)

            return web.json_response(res_js)


@server.PromptServer.instance.routes.post(END_POINT_URL_FOR_PRODUCT_4)
async def toggleAuthor(req):
    jsonData = await req.json()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            BASE_URL + END_POINT_URL_FOR_PRODUCT_4, json=jsonData
        ) as response:
            res_js = await response.json()
            data = res_js.get("data", {})
            print("res_js", res_js)

            return web.json_response(res_js)


@server.PromptServer.instance.routes.post(END_POINT_URL_FOR_PRODUCT_5)
async def toggleDistribution(req):
    jsonData = await req.json()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            BASE_URL + END_POINT_URL_FOR_PRODUCT_5, json=jsonData
        ) as response:
            res_js = await response.json()
            data = res_js.get("data", {})
            print("res_js", res_js)

            return web.json_response(res_js)


@server.PromptServer.instance.routes.post(END_POINT_FILE_IS_EXITS)
async def checkFileIsExits(req):
    # 获取请求数据
    jsonData = await req.json()

    # 获取文件路径参数
    file_name = jsonData.get("file_name")
    if not file_name:
        return web.json_response({"success": False, "errMsg": "文件路径不能为空"})
    abs_file_path = os.path.join(find_pipeline_path(), file_name)
    
    # 检查文件是否存在
    file_exists = os.path.exists(abs_file_path)

    # 返回结果
    return web.json_response({"success": True, "fileExists": file_exists})


@server.PromptServer.instance.routes.post(END_POINT_GET_WORKFLOW)
async def getWorkflowJson(req):
    # 获取请求数据
    jsonData = await req.json()
    # 获取工作流ID参数
    workflow_id = jsonData.get("workflow_id")
    if not workflow_id:
        return web.json_response({"success": False, "errMsg": "工作流ID不能为空"})
   # 直接解析工作流数据返回即可
    workflow_data = get_workflow(workflow_id)
    if not workflow_data:
        return web.json_response({"success": False, "errMsg": "工作流文件不存在或为空"})
    return web.json_response({"success": True, "workflow": workflow_data})

def find_pipeline_path():
    pipeline_path = os.path.join(find_plugin_root(), 'config', 'pipeline')
    os.makedirs(pipeline_path, exist_ok=True)
    return pipeline_path

#安全验证
def sanitize_filename(filename):
    # 1. 去除所有非字母、数字、下划线和点的字符
    sanitized = re.sub(r'[^A-Za-z0-9_.-]', '', filename)
    
    # 2. 确保文件名至少包含一个字符，并且没有连续的点
    if not sanitized or '..' in sanitized:
        raise ValueError("Invalid file name")
    
    return sanitized

def append_json_extension(filename):
    if not filename.lower().endswith('.json'):
        filename += '.json'
    return filename

def get_abs_file_path(pipeline_path, file_name):
    sanitized_file_name = sanitize_filename(file_name)
    sanitized_file_name_with_ext = append_json_extension(sanitized_file_name)
    
    # 使用 pathlib.Path 来构建和验证路径
    pipeline_path_obj = Path(pipeline_path)
    abs_file_path = (pipeline_path_obj / sanitized_file_name_with_ext).resolve()
    
    # 确保生成的路径仍然在 pipeline_path 内
    try:
        abs_file_path.relative_to(pipeline_path_obj)
    except ValueError:
        raise ValueError("File path traversal detected")

    return str(abs_file_path)

@server.PromptServer.instance.routes.post(END_POINT_DELETE_FILE)
async def deleteFile(req):
    # 获取请求数据
    jsonData = await req.json()

    # 获取文件路径参数
    file_name = jsonData.get("file_name")
    if not file_name:
        return web.json_response({"success": False, "errMsg": "文件路径不能为空"})

    # 获取冗余文件路径
    abs_file_path = get_abs_file_path(find_pipeline_path(), file_name)

    # 检查文件是否存在
    if os.path.exists(abs_file_path):
        try:
            # 尝试删除文件
            os.remove(abs_file_path)
            return web.json_response({"success": True, "message": "文件删除成功"})
        except Exception as e:
            # 处理删除文件时的异常
            return web.json_response(
                {"success": False, "errMsg": f"删除文件时出错：{str(e)}"}
            )
    else:
        return web.json_response({"success": False, "errMsg": "文件不存在"})


@server.PromptServer.instance.routes.post(END_POINT_DELETE_WORKFLOW)
async def delete_workflow(req):
    # 获取请求数据
    jsonData = await req.json()

    # 获取工作流的唯一标识 uniqueid
    uniqueid = jsonData.get("uniqueid")
    if not uniqueid:
        return web.json_response({"success": False, "errMsg": "uniqueid 不能为空"})

    try:
        # 调用 get_workflow 获取工作流数据
        workflow_data = get_workflow(uniqueid)
        if not workflow_data:
            return web.json_response(
                {"success": False, "errMsg": "未找到对应的工作流数据"}
            )

        # 构建工作流文件的绝对路径
        base_dir = os.path.abspath(
            os.path.join(
                find_plugin_root(),
                "config",
                "pipeline",
            )
        )
        abs_file_path = os.path.join(base_dir, f"{uniqueid}.json")

        # 检查文件是否存在并尝试删除
        if os.path.exists(abs_file_path):
            os.remove(abs_file_path)
            return web.json_response({"success": True, "message": "工作流文件删除成功"})
        else:
            return web.json_response({"success": False, "errMsg": "文件不存在"})

    except Exception as e:
        return web.json_response(
            {"success": False, "errMsg": f"删除工作流时出错：{str(e)}"}
        )


# 获取上传凭证，由前端直传扩展存储
@server.PromptServer.instance.routes.post("/get-upload-token")
async def get_upload_token(req):
    try:
        json_data = await req.json()

        original_file_name = json_data.get("fileName")
        if not original_file_name:
            return web.json_response({"success": False, "errMsg": "缺少文件名参数"})

        # 保留文件扩展名
        file_extension = os.path.splitext(original_file_name)[1]
        if not file_extension:
            return web.json_response({"success": False, "errMsg": "文件名缺少扩展名"})

        biz_code = "product_images"
        cloud_file_name = f"{datetime.now().strftime('%s%f')}{file_extension}"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                BASE_URL
                + UPLOAD_OSS_URL
                + f"?bizCode={biz_code}&cloudFileName={cloud_file_name}"
            ) as response:
                if response.status == 200:
                    upload_options = await response.json()
                    return web.json_response({"success": True, "data": upload_options})
                else:
                    return web.json_response(
                        {"success": False, "errMsg": "获取上传凭证失败"}
                    )
    except Exception as e:
        print(f"获取上传凭证时出错: {str(e)}")
        return web.json_response({"success": False, "errMsg": "服务器内部错误"})


@server.PromptServer.instance.routes.post(END_POINT_URL1)
async def kaji_r(req):
    try:
        # 获取请求体中的 JSON 数据
        jsonData = await req.json()
        logging.info(f"收到的请求数据: {jsonData}")

        # 提取字段
        uniqueid = jsonData.get("uniqueid") 
        workflow = jsonData.get("workflow")
        output = jsonData.get("output")

        # 检查是否缺少必要字段
        if not uniqueid:
            logging.error("请求中缺少 uniqueid 字段")
            return web.Response(status=400, text="uniqueid is missing")
        if not workflow or not output:
            logging.error("请求中缺少 workflow 或 output 字段")
            return web.Response(status=400, text="workflow or output is missing")

        # 重新格式化数据
        newData = reformat(jsonData)

        # logging.info(f"作品上传接口入参: {newData}")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                BASE_URL + END_POINT_URL_FOR_PRODUCT_2, json=newData
            ) as response:
                try:
                    # 解析响应数据
                    res = await response.text()
                    logging.info(f"收到的响应文本: {res}")
                    res_js = json.loads(res)

                    # 获取作品 ID
                    data = res_js.get("data", {})
                    PRODUCT_ID = data.get("_id", None)
                    if PRODUCT_ID is None:
                        logging.error("未能从响应中获取 PRODUCT_ID")
                        raise ValueError("未能从响应中获取 PRODUCT_ID")

                    # 检查审核状态
                    txt_audit_status = data.get("txt_audit_status", None)
                    if txt_audit_status != 1:
                        logging.error("标题或描述审核未通过，涉嫌违规")
                        raise ValueError("标题或描述审核未通过，涉嫌违规")

                    image_audit_status = data.get("image_audit_status", None)
                    if image_audit_status != 1:
                        logging.error("图片审核未通过，涉嫌违规")
                        raise ValueError("图片审核未通过，涉嫌违规")

                    # 成功处理
                    logging.info("作品上传成功")
                    # 作品上传成功再本地保存工作流数据
                    logging.info(f"正在保存工作流数据: uniqueid={uniqueid}")
                    save_workflow(uniqueid, {"workflow": workflow, "output": output})
                    return web.json_response(res_js)
                except json.JSONDecodeError:
                    logging.error("无法解析 JSON 响应")
                    return web.Response(
                        status=response.status, text="Failed to parse JSON response"
                    )
                except ValueError as e:
                    logging.error(f"值错误: {e}")
                    return web.Response(status=400, text=str(e))
    except Exception as e:
        logging.error(f"处理请求时出错: {e}")
        return web.Response(status=500, text="Internal Server Error")


#合并output和workflow文件，弄俩个顶级键来合并即可
def save_merged_data(workflow_data, output_data, file_path):
    try:
        # 映射个数据结构
        combined_data = {
            "workflow": workflow_data,
            "output": output_data
        }
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # 合并后保存
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=4)
        
        print(f"工作流文件已成功合并保存为 {file_path}")

    except Exception as e:
        print(f"工作流文件合并保存发生错误: {e}")

#解析合并文件获取output和workflow信息
def parse_merged_file(file_path):
    try:
        if not os.path.exists(file_path):
            print(f"工作流文件不存在: {file_path}")
            return {"workflow": {}, "output": {}}

        with open(file_path, 'r', encoding='utf-8') as f:
            combined_data = json.load(f)

        # 俩数据直接返回
        return {
            "workflow": combined_data.get("workflow", {}),
            "output": combined_data.get("output", {})
        }
    except json.JSONDecodeError as e:
        print(f"工作流文件解析错误: {e}")
        return {"workflow": {}, "output": {}}
    except Exception as e:
        print(f"读取工作流文件时发生错误: {e}")
        return {"workflow": {}, "output": {}}

def save_workflow(uniqueid, data):
    base_path = os.path.join(find_plugin_root(), "config/pipeline/")
    # 检查并创建主目录
    os.makedirs(base_path, exist_ok=True)
    #给个文件名
    combined_file = os.path.join(base_path, f"{uniqueid}.json")
    #合并保存数据
    save_merged_data(data.get("workflow", {}), data.get("output", {}), combined_file)



async def task_generate():
    while True:
        try:
            task_data = await gc_task_queue.get()
            # executor.submit(run_gc_task, task_data["data"])
            # 这里任务处理需要并发吗？待讨论
            # 比如机器恢复时，可能大量暂存任务同时请求过来（comfyUI的/prompt核心接口是否也支持大量并发,目前此处没开异步任务，是一个一个调用/prompt）
            # 如果改为多个协程并发访问，记得使用asyncio.Lock 来保护集合操作
            await run_gc_task_async(task_data)
            gc_task_queue.task_done()
        except asyncio.CancelledError:
            logging.error("Task was cancelled.")
        except Exception as e:
            logging.error(f"发生错误: {e}")


async def send_prompt_to_comfyui(prompt, workflow=None):
    comfyui_address = get_comfyui_address()

    data = {
        "prompt": prompt,
        "client_id": cur_client_id,
    }
    logging.info(f"发送到 ComfyUI 的 prompt 数据: {data}")
    if workflow and "extra_data" in workflow:
        data["extra_data"] = workflow["extra_data"]

    # logging.info(f"核心接口 /prompt的接口入参: {data}")
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{comfyui_address}/prompt", json=data) as response:
            if response.status == 200:
                response_json = await response.json()
                logging.info(f"核心接口 /prompt的接口出参: {response_json}")
                return response_json
            else:
                error_text = await response.text()
                logging.error(
                    f"发送prompt失败，状态码: {response.status}, 错误信息: {error_text}"
                )
                return None
            

async def get_upload_options(session, bizCode, cloudFileName):
    async with session.get(
        BASE_URL + UPLOAD_OSS_URL + f"?bizCode={bizCode}&cloudFileName={cloudFileName}"
    ) as response:
        if response.status == 200:
            return await response.json()
        else:
            print(f"获取上传配置信息失败，状态码: {response.status}")
            return None

async def upload_file_to_oss(session, url, token, key, file_path, filename):
    with open(file_path, "rb") as file:
        form_data = aiohttp.FormData()
        form_data.add_field("file", file, filename=filename)
        form_data.add_field("token", token)
        form_data.add_field("key", key)
        async with session.post(url, data=form_data) as upload_response:
            try:
                upload_data = await upload_response.json()
                print("文件上传成功：", OSS_DOMAIN+upload_data.get("key"))
                return OSS_DOMAIN+upload_data.get("key")
            except aiohttp.ClientResponseError as e:
                print("上传失败", e)
                return None
            except json.JSONDecodeError as e:
                print("解析上传结果失败", e)
                return None

async def upload_output_image(filename, bizCode="workflow_output"):
    temp_path = os.path.join(media_output_dir, filename)
    if not os.path.exists(temp_path):
        print(f"File does not exist: {temp_path}")
        return None

    async with aiohttp.ClientSession() as session:
        cloudFileName = f"{datetime.now().strftime('%s%f')}.png"
        uploadOptionsRes = await get_upload_options(session, bizCode, cloudFileName)
        if uploadOptionsRes is None:
            return None

        url = uploadOptionsRes["uploadFileOptions"]["url"]
        token = uploadOptionsRes["uploadFileOptions"]["formData"]["token"]
        key = uploadOptionsRes["uploadFileOptions"]["formData"]["key"]

        return await upload_file_to_oss(session, url, token, key, temp_path, filename)

async def upload_output_gifs(filename,bizCode="workflow_output"):
    temp_path = os.path.join(media_output_dir, filename)
    if not os.path.exists(temp_path):
        print(f"File does not exist: {temp_path}")
        return None

    async with aiohttp.ClientSession() as session:
        # 假设视频文件保持原扩展名
        cloudFileName = f"{datetime.now().strftime('%s%f')}{os.path.splitext(filename)[1]}"
        uploadOptionsRes = await get_upload_options(session, bizCode, cloudFileName)
        if uploadOptionsRes is None:
            return None

        url = uploadOptionsRes["uploadFileOptions"]["url"]
        token = uploadOptionsRes["uploadFileOptions"]["formData"]["token"]
        key = uploadOptionsRes["uploadFileOptions"]["formData"]["key"]

        return await upload_file_to_oss(session, url, token, key, temp_path, filename)


def validate_prompt(prompt):
    for node_id, node_data in prompt.items():
        if "class_type" not in node_data:
            logging.error(f"节点 {node_id} 缺少 class_type 属性")
            return False
    return True


async def run_gc_task_async(task_data):
    try:
        logging.info(f"工作队列获取任务-开始执行: {task_data}")
        if "prompt" not in task_data or "kaji_generate_record_id" not in task_data:
            logging.error(f"任务数据不完整: {task_data}")
            return
        prompt = task_data["prompt"]
        kaji_generate_record_id = task_data["kaji_generate_record_id"]

        if not validate_prompt(prompt):
            logging.error("prompt 数据无效")
            return

        result = await send_prompt_to_comfyui(prompt)
        if result and "prompt_id" in result:
            prompt_id = result["prompt_id"]

            # 本地维护关系
            taskIdDict[prompt_id] = kaji_generate_record_id
            listeningTasks.add(kaji_generate_record_id)

            # 每次通过接口调用来获取排队信息，有点太慢了，这里要快。直接返回牌号，当场算就可以
            number = result["number"]
            numberDict[prompt_id] = number
            if runningNumber == -1:
                cur_q = 0
            else:
                cur_q = number - runningNumber
            logging.info(f"立即获取当前任务的排队状态： {cur_q}")

            # 服务器也维护关系
            submit_success = {
                "type": "submit_success",
                "data": {
                    "kaji_generate_record_id": kaji_generate_record_id,
                    "prompt_id": prompt_id,
                    "number": number,
                    "uni_hash": uni_hash,
                    "cur_q": cur_q,
                },
            }
            await wss_c1.send(json.dumps(submit_success))
            logging.info(f"任务成功提交，prompt_id: {submit_success}")
        else:
            logging.error("任务提交失败")

    except Exception as e:
        logging.error(f"执行任务时发生错误: {str(e)}")
        logging.error("详细错误信息:", exc_info=True)

async def get_history_from_comfyui(prompt_id):
    comfyui_address = get_comfyui_address()  

    url = f"{comfyui_address}/history/{prompt_id}"  
    #logging.info(f"尝试从 ComfyUI 获取历史记录: {url}")

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                history_data = await response.json()
                #logging.info(f"成功获取到的历史记录数据: {history_data}")
                return history_data
            else:
                error_text = await response.text()
                logging.error(
                    f"获取历史记录失败，状态码: {response.status}, 错误信息: {error_text}"
                )
                return None
            
async def download_media_async(url, save_dir):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logging.error(f"下载媒体文件失败: {url}, 状态码: {response.status}")
                    return None

                # 从 Content-Type 或 URL 中获取文件扩展名
                content_type = response.headers.get("content-type")
                extension = (
                    mimetypes.guess_extension(content_type) or os.path.splitext(url)[1]
                )
                if not extension:
                    extension = ".bin"

                # 生成唯一文件名
                filename = f"{os.urandom(8).hex()}{extension}"
                save_path = os.path.join(save_dir, filename)

                # 确保保存目录存在
                os.makedirs(save_dir, exist_ok=True)

                # 写入文件
                with open(save_path, "wb") as file:
                    while chunk := await response.content.read(8192):
                        file.write(chunk)

                print(f"媒体文件已成功下载到: {save_path}")
                return save_path
    except Exception as e:
        logging.error(f"下载媒体文件时发生错误: {e}")
        return None


async def download_all_media(form_data):
    download_tasks = []

    for key, value in form_data.items():
        # 如果字段包含 URL，则创建下载任务
        if isinstance(value, dict) and "url" in value:
            url = value["url"]
            download_tasks.append(download_media_async(url, media_save_dir))

    # 并发等待所有任务完成
    downloaded_paths = await asyncio.gather(*download_tasks)
    return downloaded_paths


def update_output_from_form_data(form_data, output, downloaded_paths):
    download_index = 0

    for key, value in form_data.items():
        # 分解 key，"KSampler:sampler_name" -> ["KSampler", "sampler_name"]
        key_parts = key.split(":")
        if not key_parts:
            continue

        # 找到对应的 output 项
        output_item = None
        for output_key, output_value in output.items():
            if output_value["class_type"] == key_parts[0]:
                output_item = output_value
                break

        if not output_item:
            logging.warning(f"未找到匹配的 class_type: {key_parts[0]}，跳过 {key}")
            continue

        # 定位到 inputs 部分，根据后续的 key_parts 更新字段
        current = output_item.get("inputs", {})
        for part in key_parts[1:-1]:
            current = current.setdefault(part, {})

        # 如果是媒体文件，替换为本地路径
        if isinstance(value, dict) and "url" in value:
            local_path = downloaded_paths[download_index]
            download_index += 1
            if local_path:
                current[key_parts[-1]] = os.path.basename(local_path)  
            else:
                logging.error(f"媒体文件下载失败: {value['url']}")
        else:
            # 直接更新字段
            current[key_parts[-1]] = value


async def deal_recv_generate_data(recv_data):
    # 获取 uniqueid 和任务 ID
    uniqueid = recv_data["uniqueid"]
    kaji_generate_record_id = recv_data["kaji_generate_record_id"]
    form_data = recv_data["formData"]

    # 从 uniqueid 加载对应的 output
    output = get_output(uniqueid)

    # 等待下载所有媒体文件才能生成
    # 下载失败或其他插件端生成异常，如果没有同步到生成失败的状态去退款，可能需要一个统一的超时处理执行退款等炒作
    downloaded_paths = await download_all_media(form_data)

    # 更新 output 数据
    update_output_from_form_data(form_data, output, downloaded_paths)

    # 预处理并继续后续操作
    await pre_process_data(kaji_generate_record_id, output)


async def pre_process_data(kaji_generate_record_id, output):
    try:
        # 通过查看comfyui原生缓存机制定位到，调用prompt接口不会自动修改Ksample中的随机种子值，导致走了缓存逻辑，所以直接跳过了所有步骤。
        # （缓存机制在execution.py-->execute函数-->recursive_output_delete_if_changed函数）
        # 这里手动重置随机种子值
        for item in output.values():
            if item.get("class_type") == "KSampler":
                # 这个随机数只需要和上次生图不一样就行，seed的位数为15位
                item["inputs"]["seed"] = random.randint(10**14, 10**15 - 1)

        # 使用收到的输入数据生图
        # 准备任务数据
        task_data = {
            "kaji_generate_record_id": kaji_generate_record_id,
            "prompt": output,
        }

        # 将任务添加到队列
        await gc_task_queue.put(task_data)
        print("任务(包含工作流的数据)添加至工作队列。")
    except Exception as e:
        print(f"处理数据时发生错误: {e}")

#留这俩函数不改之前调用处的逻辑了
def get_output(uniqueid, path="config/pipeline/"):
    base_path = os.path.join(find_plugin_root(), path)
    combined_file = os.path.join(base_path, f"{uniqueid}.json")
    parsed_data = parse_merged_file(combined_file)
    return parsed_data.get("output", {})


def get_workflow(uniqueid, path="config/pipeline/"):
    base_path = os.path.join(find_plugin_root(), path)
    combined_file = os.path.join(base_path, f"{uniqueid}.json")
    parsed_data = parse_merged_file(combined_file)
    return parsed_data.get("workflow", {})



def find_project_root():
    script_directory = os.path.dirname(os.path.abspath(__file__))
    relative_path = script_directory + "../../../"
    absolute_path = os.path.abspath(relative_path)
    if not absolute_path.endswith(os.sep):
        absolute_path += os.sep
    return absolute_path


def find_plugin_root():
    script_directory = os.path.dirname(os.path.abspath(__file__))
    if not script_directory.endswith(os.sep):
        script_directory += os.sep
    return script_directory


def thread_run():
    logging.info(f"咔叽插件网络资源初始化：如 websocket、异步队列等")
    # 只开启一个线程
    threading.Thread(target=run_asyncio_in_thread, daemon=True).start()


# 线程内使用asyncio管理所有异步任务；队列也改为异步队列 test
def run_asyncio_in_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)  
    loop.run_until_complete(
        asyncio.gather(
            handle_websocket(1),
            handle_websocket(2),
            task_generate(),
        )
    )
