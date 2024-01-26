#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Improve from https://gist.github.com/Sg4Dylan/cb2c1d0ddb4559c2c46511de31ca3251
# Licence: GPLv3

import requests
import re
import json
import time
import logging

REGX_XUNLEI = re.compile('''
^(?:
    7\.|sd|xl|-XL|xun|
    unknown\s(?:
        bt/7\.(?!
            (?:9|10)\.\d\D  | # BitTorrent
            0\.0\.0$          # BitTorrent?
        )|
        sd|xl
    )
)
''', re.I|re.X)
REGX_PLAYER = re.compile('''
^(?:
    dan               | # DanDan (DL)
    DLB|dlb           | # DLBT (DL)
    [Qq]vo            | # Qvod (QVOD) [Dead]
    [Ss]od            | # Soda
    [Tt]orc           | # Torch (TB)
    [Vv]ag            | # Vagaa (VG) [Dead?]
    [Xx]fp            | # Xfplay (XF)
    Unknown\s(?:
        DL            | # DanDan/DLBT (DL)
        QVO           | # Qvod (QVOD) [Dead]
        TB            | # Torch (TB)
        UW            | # uTorrent Web (UW)
        VG            | # Vagaa (VG) [Dead?]
        XF              # Xfplay (XF)
    )
)
''', re.X)
REGX_OTHERS = re.compile('''
^(?:
    caca              | # Cacaoweb
    [Ff]lash[Gg]      | # FlashGet (FG)
    .+?ransp          | # Net Transport (NX) - need more infomation
    [Qq]{2}           | # QQ (QD) [Dead?]
    [Tt]uo            | # TuoTu (TT) [Dead?]
    Unknown\s(?:
        BN            | # Baidu (BN) [Dead?]
        FG            | # FlashGet (FG)
        NX            | # Net Transport (NX)
        QD            | # QQ (QD) [Dead?]
        TT              # TuoTu (TT) [Dead?]
    )
)
''', re.X)

class PeerInfo:
    IP = ''
    Progress = 0
    Uploaded = 0
    Downloaded = 0
    TorrentSize = 0
    Client = ''

    def __init__(self, peer, torrent):
        def parse_ip(ip):
            if ip.startswith('::ffff:'):
                ip = ip[7:]
            return ip
        self.IP = parse_ip(peer['ip'])
        self.Progress = peer['progress']
        self.Uploaded = peer['uploaded']
        self.Downloaded = peer['downloaded']
        self.Client = peer['client']
        self.TorrentSize = torrent['size']

class ClientInfo:
    IsBanned = False
    Expires = 0
    Torrents = {}
    IP = ''
    Client = ''

    def __init__(self, peer):
        self.IP = peer.IP
        self.Client = peer.Client

class ConfigManager:
    __DEFAULT_CONFIG__ = {
        'interval_seconds': 5,
        'ban_seconds': 3600,
        'ban_xunlei': True,
        'ban_player': True,
        'ban_others': True,
        'ban_without_ratio_check': True,
        'all_client_ratio_check': True
    }

    def __init__(self, file='./config.json'):
        f = open(file)
        content = f.read()
        f.close()
        self.config = json.loads(content)

    def get(self, key):
        try:
            return self.config[key]
        except KeyError:
            val = self.get_default()
            self.config[key] = val
            return val

    def get_default(self, key):
        try:
            return self.__DEFAULT_CONFIG__[key]
        except:
            return None

class QbTorrentPeersInfo:

    ACTIVE_TORRENTS_ONLY = True

    def __init__(self, api_url, requests_session, basicauth = None):
        self.SESSION = requests_session
        self.API_FULL = api_url
        self.BASIC_AUTH = basicauth
    
    def get_peers(self, mission_hash):
        return self.SESSION.get(
            f'{self.API_FULL}/sync/torrentPeers?hash={mission_hash}',
            auth=self.BASIC_AUTH
        ).json()
    
    def get_peers_by_hash(self):
        torrents = self.SESSION.get(
            f'{self.API_FULL}/torrents/info',
            auth=self.BASIC_AUTH
        ).json()
        converted_torrents = {}
        for torrent in torrents:
            if self.ACTIVE_TORRENTS_ONLY and torrent['state'] not in ['uploading', 'downloading']:
                continue
            torrent_peers = self.get_peers(torrent['hash'])
            converted_peers = []
            for ip_port, peer in torrent_peers['peers'].items():
                converted_peers.append(PeerInfo(peer, torrent))
            converted_torrents[torrent['hash']] = converted_peers
        return converted_torrents
    
    def get_peers_by_ip(self):
        peers_hash = self.get_peers_by_hash()
        peers_ip = {}
        peers_torrents = {}
        def make_sure_peer_is_created(peer):
            try:
                peers_ip[peer.IP]
            except KeyError:
                peers_ip[peer.IP] = ClientInfo(peer)
                peers_torrents[peer.IP] = {}
        for torrent_hash, peers in peers_hash.items():
            for peer in peers:
                make_sure_peer_is_created(peer)
                peers_torrents[peer.IP][torrent_hash] = peer
        for key, value in peers_torrents.items():
            peers_ip[key].Torrents = value
        return peers_ip


class VampireHunter:

    SESSION = requests.Session()
    API_PREFIX = 'http://127.0.1.1:11451'
    API_SUFFIX = '/api/v2'
    # WebUI 用户名密码
    API_USERNAME = 'admin'
    API_PASSWORD = 'yjsnpi'
    # 如果你套了 nginx 做额外的 basicauth
    BASICAUTH_ENABLED = False
    BASICAUTH_USERNAME = '114514'
    BASICAUTH_PASSWORD = '1919810'
    # 检测间隔
    INTERVAL_SECONDS = 2
    # 屏蔽时间
    DEFAULT_BAN_SECONDS = 3600
    # 屏蔽开关
    BAN_XUNLEI = True
    BAN_PLAYER = True
    BAN_OTHERS = True
    # 识别到客户端直接屏蔽不管是否存在上传
    BAN_WITHOUT_RATIO_CHECK = True
    # 对不匹配上面屏蔽的客户端启用下载进度检查
    ALL_CLIENT_RATIO_CHECK = True

    __client_behavior_cache__ = {}
    __banned_ips = {}
    logging.basicConfig(level=logging.INFO)

    def __init__(self):
        self.load_config()
        self.API_FULL = f'{self.API_PREFIX}{self.API_SUFFIX}'
        self.login_status = self.SESSION.post(
            f'{self.API_FULL}/auth/login',
            data={
                'username': self.API_USERNAME,
                'password': self.API_PASSWORD
            }
        ).text
        logging.warning(f'Login status: {self.login_status}')
        self.__peers_info = QbTorrentPeersInfo(self.API_FULL, self.SESSION, self.get_basicauth())

    def load_config(self):
        self.config = ConfigManager()
        self.API_PREFIX = self.config.get('api_prefix')
        self.API_USERNAME = self.config.get('api_username')
        self.API_PASSWORD = self.config.get('api_password')
        basic_auth_config = self.config.get('basic_auth')
        if basic_auth_config == None:
            self.BASICAUTH_ENABLED = False
        else:
            self.BASICAUTH_ENABLED = True
            self.BASICAUTH_USERNAME = basic_auth_config['username']
            self.BASICAUTH_PASSWORD = basic_auth_config['password']
        self.INTERVAL_SECONDS = self.config.get('interval_seconds')
        self.DEFAULT_BAN_SECONDS = self.config.get('ban_seconds')
        self.BAN_XUNLEI = self.config.get('ban_xunlei')
        self.BAN_PLAYER = self.config.get('ban_player')
        self.BAN_OTHERS = self.config.get('ban_others')
        self.BAN_WITHOUT_RATIO_CHECK = self.config.get('ban_without_ratio_check')
        self.ALL_CLIENT_RATIO_CHECK = self.config.get('all_client_ratio_check')

    def get_basicauth(self):
        if self.BASICAUTH_ENABLED:
            return (self.BASICAUTH_USERNAME, self.BASICAUTH_PASSWORD)
        else:
            return None
    
    def sumbit_banned_ips(self):
        ips = ''
        now = time.time()
        tmp_banned_ips = self.__banned_ips.copy()
        for key, value in tmp_banned_ips.items():
            if now > value['expires']:
                del self.__banned_ips[key]
                continue
            ips += key + '\n'
        self.SESSION.post(
            f'{self.API_FULL}/app/setPreferences',
            auth=self.get_basicauth(),
            data={
                'json': json.dumps({
                    'banned_IPs': ips
                })
            }
        )
    
    def banip(self, ip):
        self.__banned_ips[ip] = {
            'expires': time.time() + self.DEFAULT_BAN_SECONDS
        }

    def get_client_history_behavior(self, client_ip):
        try:
            return self.__client_behavior_cache__[client_ip]
        except KeyError:
            return None

    def set_client_history_behavior(self, client_ip, behavior):
        try:
            self.__client_behavior_cache__[client_ip]
        except KeyError:
            self.__client_behavior_cache__[client_ip] = {
                'expires': time.time() + self.DEFAULT_BAN_SECONDS,
                'initial': behavior,
            }
        self.__client_behavior_cache__[client_ip]['behavior'] = behavior

    def client_history_cleanup(self):
        now = time.time()
        tmp = self.__client_behavior_cache__.copy()
        for key, value in tmp.items():
            if now > value['expires']:
                del self.__client_behavior_cache__[key]
    
    def do_once_banip(self):
        # 检查 UA
        def check_peer_client(peer):
            client_string = peer.Client
            # 屏蔽迅雷
            if self.BAN_XUNLEI and REGX_XUNLEI.search(client_string):
                return True
            # 屏蔽 P2P 播放器
            if self.BAN_PLAYER and REGX_PLAYER.search(client_string):
                return True
            # 屏蔽野鸡客户端
            if self.BAN_OTHERS and REGX_OTHERS.search(client_string):
                return True
            return False
        
        # 检查下载行为
        def check_progress(previous_behavior, current_behavior):
            for torrent, previous in previous_behavior['behavior'].items():
                try:
                    initial = previous_behavior['initial'][torrent]
                except KeyError:
                    previous_behavior['initial'][torrent] = previous
                    continue
                try:
                    current = current_behavior[torrent]
                except KeyError:
                    continue
                if current.Uploaded == 0:
                    continue
                logging.debug(f'[{current.IP}:{current.Client}] Current: Upload {current.Uploaded}, Progress {current.Progress}, Previous: Upload {previous.Uploaded}, Progress {previous.Progress}, Initial: Upload {initial.Uploaded}, Progress {initial.Progress}')
                if current.Progress == 0 and current.Uploaded > (current.TorrentSize * 0.001) and current.Uploaded > 10000:
                    logging.info(f'[{current.IP}:{current.Client}] Detected strange client, Current Progress: {current.Progress}, Uploaded: {current.Uploaded}.')
                    return True
                if (current.Progress - initial.Progress) <= 0 and (current.Uploaded - initial.Uploaded) > (current.TorrentSize * 0.001):
                    logging.info(f'[{current.IP}:{current.Client}] Detected strange client, Current Progress: {current.Progress}, Uploaded: {current.Uploaded}, Previous: Progress {previous.Progress}, Upload {previous.Uploaded}, Initial: Progress {initial.Progress}, Upload {initial.Uploaded}.')
                    return True
            return False

        peers = self.__peers_info.get_peers_by_ip()
        peers_count = 0
        for ip, peer in peers.items():
            peers_count += 1
            is_target_client = check_peer_client(peer)
            # 不检查分享率及下载进度直接屏蔽
            if self.BAN_WITHOUT_RATIO_CHECK and is_target_client:
                logging.info(f'[{ip}:{peer.Client}] Banned cause by client software.')
                self.banip(ip)
            # 其他客户端是否检查下载进度
            if not self.ALL_CLIENT_RATIO_CHECK and not is_target_client:
                continue
            logging.debug(f'[{ip}:{peer.Client}] Checking ratio.')
            previous_behavior = self.get_client_history_behavior(ip)
            current_behavior = peer.Torrents
            self.set_client_history_behavior(ip, current_behavior)
            if previous_behavior == None:
                logging.debug(f'[{ip}:{peer.Client}] New IP, Creating ratio historiy.')
                continue
            # 分享率及下载进度异常
            if check_progress(previous_behavior, current_behavior):
                logging.info(f'[{ip}:{peer.Client}] Banned cause by behavior.')
                self.banip(ip)
        logging.debug(f'Round finished, checked {peers_count} peers.')
        self.sumbit_banned_ips()
        self.client_history_cleanup()
    
    def start(self):
        if 'Fails' in self.login_status:
            logging.warning('Please check login credentials.')
            return
        while True:
            self.do_once_banip()
            time.sleep(self.INTERVAL_SECONDS)


if __name__ == '__main__':
    hunter = VampireHunter()
    hunter.start()
