# Mirouter-6500pro Device Tracker

这是一个 Home Assistant 插件，用于追踪 小米路由器6500pro 所无线连接的设备。

## 安装
```
1. 下载并解压插件代码到 Home Assistant 配置目录下的 `custom_components/mirouter` 目录。
2. 确保目录结构如下：
    ├── custom_components/
    │   └── mirouter/
        │       ├── __init__.py
        │       ├── manifest.json
        │       ├── device_tracker.py
        │       └── encrypt.py
3. 在 Home Assistant 配置文件 `configuration.yaml` 中添加以下内容：

  device_tracker:
    - platform: mirouter
      host: YOUR_ROUTER_IP
      password: YOUR_ROUTER_PASSWORD
      scan_interval: 60
4.重新启动 Home Assistant。
```
## 使用

插件安装完成后，您可以在 Home Assistant 中设置-设备与服务-实体中查看小米6500pro路由所连接的无线设备。
