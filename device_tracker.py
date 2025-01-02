"""Provide a device tracker for Mi Router.

It includes functionality to authenticate with the router,
retrieve connected device information, and periodically update
the device list.
"""

import datetime
import json
import logging

import aiohttp
import voluptuous as vol

from homeassistant.components.device_tracker import (
    CONF_SCAN_INTERVAL,
    PLATFORM_SCHEMA as DEVICE_TRACKER_PLATFORM_SCHEMA,
    AsyncSeeCallback,
)
from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.util import Throttle

from .encrypt import Encrypt

_LOGGER = logging.getLogger(__name__)
# 定义扫描间隔（单位：秒），这里设为60秒，可根据实际调整
DEFAULT_SCAN_INTERVAL = datetime.timedelta(seconds=60)

MIRouter_PLATFORM_SCHEMA = DEVICE_TRACKER_PLATFORM_SCHEMA.extend(
    {
        # 路由器IP地址配置项
        vol.Required("host"): cv.string,
        # 路由器密码配置项
        vol.Required("password"): cv.string,
        vol.Optional(
            CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL
        ): cv.time_period_seconds,
    }
)


class RouterDeviceScanner:
    """代表路由器设备扫描器的类，用于获取连接设备信息."""

    def __init__(self, host: str, username: str, password: str, see) -> None:
        """初始化相关属性."""
        _LOGGER.debug("初始化 RouterDeviceScanner")
        self.host = host
        self.username = username
        self.password = password
        self.encryptor = Encrypt()
        # 初始化时可以创建Encrypt对象，避免在get_param每次重新创建
        self.param_cache = None
        self.stok = None
        self.see = see
        self.devices: list[dict] = []
        self.last_results: dict = {}

    def _get_param(self):
        if not self.param_cache:
            nonce = self.encryptor.init()
            old_pwd = self.encryptor.old_pwd(self.password)
            self.param_cache = {
                "username": self.username,
                "password": old_pwd,
                "logtype": 2,
                "nonce": nonce,
            }
        return self.param_cache

    async def _get_stok(self, session):
        param = self._get_param()
        loginurl = f"http://{self.host}/cgi-bin/luci/api/xqsystem/login"

        async with session.post(loginurl, data=param) as rsp:
            if rsp.status == 200:
                response_json = json.loads(await rsp.text())
                self.stok = response_json.get("token")
            else:
                _LOGGER.error("登录路由器获取 token 失败，状态码: %s", rsp.status)

    async def async_get_device_info(self):
        """异步获取设备详细信息（MAC、IP、名称）."""
        device_info = []

        try:
            async with aiohttp.ClientSession() as session:
                # 这里需要替换为路由器真实的获取设备信息的API地址，假设为 /api/connected_devices_info
                # stok = await self._get_stok(session)
                if self.stok is None:
                    await self._get_stok(session)
                else:
                    url = f"http://{self.host}/cgi-bin/luci/;stok={self.stok}/api/misystem/devicelist?mlo=1"
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = json.loads(await response.text())
                            if "msg" in data and data["msg"] == "Invalid token":
                                _LOGGER.error("获取设备信息失败,token 失效")
                                await self._get_stok(session)
                            else:
                                _LOGGER.debug("获取设备信息成功")
                                device_list = [
                                    device
                                    for device in data["list"]
                                    if device["type"] != 0
                                ]
                                for device in device_list:
                                    mac_address = device["mac"]
                                    ip_address = device["ip"][0]["ip"]
                                    device_name = device["name"]
                                    is_online = device["online"]
                                    device_info.append(
                                        {
                                            "mac": mac_address,
                                            "ip": ip_address,
                                            "name": device_name,
                                            "online": is_online,
                                        }
                                    )
                        else:
                            _LOGGER.error(
                                "获取设备信息失败，状态码: %s", response.status
                            )
        except aiohttp.ClientError as e:
            _LOGGER.error("请求出现异常: %s", e)
        return device_info

    @Throttle(DEFAULT_SCAN_INTERVAL)
    async def async_update_info(self):
        """异步更新设备信息，调用获取设备信息方法并保存结果."""
        self.devices = await self.async_get_device_info()
        self.last_results = {device["mac"]: device for device in self.devices}
        for device in self.devices:
            await self.see(
                mac=device["mac"],
                dev_id=device["mac"].replace(":", "_"),
                host_name=device["name"],
                source_type="router",
                attributes={
                    "online": device["online"],
                    "ip": device["ip"],
                    "unique_id": device["mac"],
                },
            )


async def async_setup_scanner(
    hass: HomeAssistant,
    config: ConfigType,
    see: AsyncSeeCallback,
    discovery_info: DiscoveryInfoType | None,
) -> bool:
    """异步设置扫描器并启动定期扫描."""
    host = config["host"]
    router_username = "admin"
    router_password = config["password"]
    scanner = RouterDeviceScanner(host, router_username, router_password, see)
    _LOGGER.debug("初始化 RouterDeviceScanner 完成")

    # 启动定期更新设备信息的任务
    async def _update(_):
        _LOGGER.debug("开始更新设备信息")
        await scanner.async_update_info()

    # scan_interval_seconds = config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    # scan_interval = datetime.timedelta(seconds=scan_interval_seconds)
    scan_interval = config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    async_track_time_interval(hass, _update, scan_interval)
    return True
