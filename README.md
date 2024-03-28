# qBittorrent Ban Vampire

改自 [https://gist.github.com/Sg4Dylan/cb2...](https://gist.github.com/Sg4Dylan/cb2c1d0ddb4559c2c46511de31ca3251)

## Key Features

- 使用 qBittorrent Web API，支持原版 qBittorrent
- 改进的客户端行为检测
- 支持对所有客户端进行无关 User Agent 的行为检查
- 配置改到配置文件里面，可以通过 `git pull` 一键更新

## 配置文件说明

```jsonc
{
    // API 地址，也可以说是 qBittorrent Web UI 界面的地址
    "api_prefix": "http://127.0.1.1:4514",
    // 进入 qBittorrent Web UI 的用户名
    "api_username": "admin",
    // 进入 qBittorrent Web UI 的密码
    "api_password": "yjsnpi",
    // HTTP Basic Auth ，如果你套了 nginx 可能会有用，如果你不知道是什么可以直接删掉这一行和下面三行
    "basic_auth": {
        "username": null,
        "password": null
    },
    // 检测间隔时间
    "interval_seconds": 5,
    // 检测到奇怪行为以后封锁多久（秒）
    "ban_seconds": 3600,
     // 是否封锁迅雷
    "ban_xunlei": true,
    // 是否封锁 P2P 播放器
    "ban_player": true,
    // 是否封锁其他的野鸡客户端
    "ban_others": true,
    // 封锁其他自定义的客户端名, 使用正则表达式进行匹配, 例如: "^Taipie", 表示匹配Taipie开头的客户端
    "ban_customs": [],
    // 封锁上面四个种类的野鸡客户端的时候，是否不检查行为直接封锁
    "ban_without_ratio_check": true,
    // 是否对其他所有客户端都进行行为检测
    "all_client_ratio_check": true
}
```

配置文件只支持`//`开头的注释，请拿 `config.default.json` 改。放到工作目录下，且将文件命名成 `config.json`。
