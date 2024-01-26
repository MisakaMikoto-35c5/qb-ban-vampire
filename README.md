# qBittorrent Ban Vampire

改自 [https://gist.github.com/Sg4Dylan/cb2...](https://gist.github.com/Sg4Dylan/cb2c1d0ddb4559c2c46511de31ca3251)

## Key Features

- 使用 qBittorrent Web API，支持原版 qBittorrent
- 改进的客户端行为检测
- 支持对所有客户端进行无关 User Agent 的行为检查
- 配置改到配置文件里面，可以通过 `git pull` 一键更新

## 配置文件说明

```
{
    "api_prefix": "API 地址，也可以说是 qBittorrent Web UI 界面的地址",
    "api_username": "进入 qBittorrent Web UI 的用户名",
    "api_password": "进入 qBittorrent Web UI 的密码",
    "basic_auth": { // HTTP Basic Auth ，如果你套了 nginx 可能会有用，如果你不知道是什么可以直接删掉这一行和下面三行
        "username": null,
        "password": null
    },
    "interval_seconds": 3, // 检测间隔时间
    "ban_seconds": 3600, // 检测到奇怪行为以后封锁多久（秒）
    "ban_xunlei": true, // 是否封锁迅雷
    "ban_player": true, // 是否封锁 P2P 播放器
    "ban_others": true, // 是否封锁其他的野鸡客户端
    "ban_without_ratio_check": true, // 封锁上面三个种类的野鸡客户端的时候，是否不检查行为直接封锁
    "all_client_ratio_check": true // 是否对其他所有客户端都进行行为检测
}
```

配置文件不能包含注释，请直接拿 `config.json` 改。配置文件必须在工作目录下，且文件名必须为 `config.json`。
