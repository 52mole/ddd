#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import json
import hashlib
import threading
import os
from struct import pack, unpack
from multiprocessing import Process

SECRET_KEY = b"^FStx,wl6NquAVRF@f%6\x00"

serial_num = 0
user_id = 0
session_bytes = bytes()


def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def build_login_token(session, server_id):
    start1 = int.from_bytes(session[3:7], 'big')
    start2 = int.from_bytes(session[10:14], 'big')
    fixed_str = "fREd hAo crAzy BAby in Our ProgRAm?"
    s = str(start2) + fixed_str[5:16] + str(start1)
    md5_result = md5_hash(s)
    return md5_result[5:22].encode('ascii')


def get_hex(num):
    return f"{num:08X}"


class Packet:
    def __init__(self, data=None):
        if data is None:
            self.length = 0
            self.serial_num = 0
            self.cmd_id = 0
            self.user_id = 0
            self.version = 0
            self.body = bytes()
        else:
            if isinstance(data, str):
                data = bytes.fromhex(data)
            if len(data) >= 17:
                self.length, self.serial_num, self.cmd_id, self.user_id, self.version = unpack("!IBIII", data[:17])
                self.body = data[17:]
            else:
                self.length, self.serial_num, self.cmd_id, self.user_id, self.version = 0, 0, 0, 0, 0
                self.body = bytes()

    def data(self):
        head = pack("!IBIII", self.length, self.serial_num, self.cmd_id, self.user_id, self.version)
        return head + self.body

    def get_serial_num(self):
        global serial_num, user_id
        self.length = len(self.body) + 18
        self.user_id = user_id
        self.version = 0
        if self.cmd_id == 201:
            serial_num = 65
        else:
            crc = 0
            for i in range(len(self.body)):
                crc ^= self.body[i]
            serial_num = (serial_num - int(serial_num / 7) + 147 + (self.length - 1) % 21 + 
                         self.cmd_id % 13 + crc) % 256
        self.serial_num = serial_num

    def encrypt(self):
        self.get_serial_num()
        res = bytearray(len(self.body) + 1)
        key_index = 0
        for index in range(len(self.body)):
            res[index] = self.body[index] ^ SECRET_KEY[key_index % 21]
            key_index += 1
            if key_index == 22:
                key_index = 0
        for index in range(len(res) - 1, 0, -1):
            res[index] |= res[index - 1] >> 3
            res[index - 1] = (res[index - 1] << 5) % 256
        res[0] |= 3
        self.body = res
        return self

    def decrypt(self):
        if len(self.body) == 0:
            return
        res = bytearray(len(self.body) - 1)
        key_index = 0
        for index in range(len(res)):
            res[index] = (self.body[index] >> 5) | (self.body[index + 1] << 3) % 256
            res[index] ^= SECRET_KEY[key_index % 21]
            key_index += 1
            if key_index == 22:
                key_index = 0
        self.body = res


class Client:
    def __init__(self):
        self.login_socket = None
        self.main_socket = None
        self.connected = False
        self.recv_buffer = bytearray()
        self.heartbeat_thread = None
        self.heartbeat_running = False
        self.send_lock = threading.Lock()
    
    def connect_login_server(self):
        try:
            self.login_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.login_socket.settimeout(10)
            self.login_socket.connect(("123.206.131.236", 1863))
            print("[+] 认证服务器已连接")
            return True
        except Exception as e:
            print(f"[-] 认证服务器连接失败: {e}")
            return False
    
    def login_server_auth(self, username, password, server_id):
        global user_id, session_bytes
        try:
            pwd_hash = md5_hash(md5_hash(password))
            
            first_packet = bytearray([
                0x00,0x00,0x00,0x93,0x01,0x00,0x00,0x00,0x67
            ])
            first_packet.extend(int(username).to_bytes(4, 'big'))
            first_packet.extend(bytes([0x00,0x00,0x00,0x00]))
            first_packet.extend(pwd_hash.encode('ascii'))
            first_packet.extend(pack("!III", 0, 1, 0))
            first_packet.extend(bytes(22))
            first_packet.extend(bytes(64))
            
            self.login_socket.send(bytes(first_packet))
            
            self.login_socket.settimeout(1.2)
            resp_data = bytearray()
            try:
                while True:
                    chunk = self.login_socket.recv(4096)
                    if not chunk:
                        break
                    resp_data.extend(chunk)
            except socket.timeout:
                pass
            
            if len(resp_data) < 37:
                print("[-] 认证响应无效")
                return False
            
            session_16 = resp_data[21:37]
            verify_packet = bytearray()
            verify_packet.extend(pack("!I", 37))
            verify_packet.append(1)
            verify_packet.extend(pack("!I", 105))
            verify_packet.extend(int(username).to_bytes(4, 'big'))
            verify_packet.extend(pack("!I", 0))
            verify_packet.extend(session_16)
            verify_packet.extend(bytes(4))
            
            self.login_socket.send(bytes(verify_packet))
            server_select_packet = bytearray()
            server_select_packet.extend(pack("!I", 205))
            server_select_packet.append(1)
            server_select_packet.extend(pack("!I", 106))
            server_select_packet.extend(int(username).to_bytes(4, 'big'))
            server_select_packet.extend(pack("!I", 0))
            server_select_packet.extend(pack("!I", server_id))
            server_select_packet.extend(pack("!I", server_id))
            server_select_packet.extend(pack("!I", 44))
            server_select_packet.extend(bytes(205 - len(server_select_packet)))
            
            self.login_socket.send(bytes(server_select_packet))
            
            self.login_socket.settimeout(2.0)
            final_resp = bytearray()
            try:
                while True:
                    chunk = self.login_socket.recv(4096)
                    if not chunk:
                        break
                    final_resp.extend(chunk)
            except socket.timeout:
                pass
            
            if len(final_resp) == 0:
                print("[-] 认证失败")
                return False
            
            session_bytes = session_16 + bytes(96)
            user_id = int(username)
            
            print(f"[+] 认证成功 (S{server_id})")
            return True
            
        except Exception as e:
            print(f"[-] 认证错误: {e}")
            return False
    
    def connect_main_server(self, server_id):
        if server_id == 1:
            port = 1965
        elif 2 <= server_id <= 30:
            port = 1865
        elif 31 <= server_id <= 100:
            port = 1201
        else:
            print(f"[-] 无效服务器: {server_id}")
            return False
        
        try:
            self.main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.main_socket.settimeout(10)
            self.main_socket.connect(("123.206.131.236", port))
            print(f"[+] 主服务器已连接")
            return True
        except Exception as e:
            print(f"[-] 主服务器连接失败: {e}")
            return False
    
    def main_server_login(self, server_id):
        global user_id, session_bytes
        try:
            token = build_login_token(session_bytes, server_id)
            token_modified = bytearray(token)
            token_modified[0] = server_id
            
            body = bytearray()
            body.append(0x00)
            body.extend(token_modified)
            body.extend(pack("!I", 16))
            body.extend(session_bytes[:16])
            body.extend(pack("!I", 0))
            body.append(0x30)
            body.extend(bytes(63))
            packet = Packet()
            packet.cmd_id = 201
            packet.user_id = user_id
            packet.body = bytes(body)
            packet.encrypt()
            
            packet_data = packet.data()
            self.main_socket.send(packet_data)
            
            header = self.main_socket.recv(17)
            if len(header) < 17:
                print(f"[-] Header无效: {len(header)}")
                return False
            
            packet_len = int.from_bytes(header[:4], "big")
            body_len = packet_len - 17
            body = b""
            while len(body) < body_len:
                chunk = self.main_socket.recv(body_len - len(body))
                if not chunk:
                    break
                body += chunk
            
            response = header + body
            
            if len(response) < packet_len:
                print("[-] 响应不完整")
                return False
            
            resp_packet = Packet(response)
            resp_packet.decrypt()
            
            if resp_packet.version != 0:
                print(f"[-] 登录失败: {resp_packet.version}")
                return False
            
            self.connected = True
            self.main_socket.settimeout(None)
            print("[+] 登录成功")
            
            threading.Thread(target=self.recv_loop, daemon=True).start()
            self.start_heartbeat()
            
            return True
            
        except Exception as e:
            print(f"[-] 登录错误: {e}")
            return False
    
    def recv_loop(self):
        while self.connected:
            try:
                data = self.main_socket.recv(4096)
                if not data:
                    self.connected = False
                    break
                
                self.recv_buffer.extend(data)
                
                while len(self.recv_buffer) >= 4:
                    packet_len = int.from_bytes(self.recv_buffer[:4], "big")
                    if packet_len <= len(self.recv_buffer):
                        packet_data = self.recv_buffer[:packet_len]
                        self.recv_buffer = self.recv_buffer[packet_len:]
                        
                        packet = Packet(packet_data)
                        packet.decrypt()
                    else:
                        break
            except Exception:
                self.connected = False
                break

    def start_heartbeat(self):
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
    
    def _heartbeat_loop(self):
        while self.heartbeat_running and self.connected:
            try:
                time.sleep(30)
                if not self.connected:
                    break
                
                packet = Packet()
                packet.cmd_id = 40
                packet.user_id = user_id
                packet.body = bytes([0x00])
                
                with self.send_lock:
                    packet.encrypt()
                    self.main_socket.send(packet.data())
                
            except Exception:
                break
    
    def stop_heartbeat(self):
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=1)
    
    def send_packet(self, packet):
        if not self.connected or not self.main_socket:
            return False
        try:
            with self.send_lock:
                packet.encrypt()
                self.main_socket.send(packet.data())
            return True
        except Exception:
            self.connected = False
            return False
    
    def close(self):
        self.connected = False
        self.stop_heartbeat()
        if self.login_socket:
            try:
                self.login_socket.close()
            except:
                pass
        if self.main_socket:
            try:
                self.main_socket.close()
            except:
                pass


def run_ddd(client, duration_minutes):
    """刷点点豆"""
    ddd_packets = [
        "0000000000000001F500000000000000000002737200000001",
        "0000000000000004DB0000000000000000000000790000000100000001",
        "0000000000000017850000000000000000000000010002E96400000001",
        "0000000000000017850000000000000000000000010002E96400000001",
        "0000000000000017850000000000000000000000010002E96400000001",
        "0000000000000017850000000000000000000000010002E96400000001",
        "0000000000000017850000000000000000000000010002E96400000001",
    ]
    
    start_time = time.time()
    end_time = start_time + duration_minutes * 60
    send_count = 0
    
    print(f"[*] 开始刷点点豆，持续 {duration_minutes} 分钟...")
    
    while time.time() < end_time:
        if not client.connected:
            print("[!] 连接断开")
            break
        
        for packet_hex in ddd_packets:
            if not client.connected:
                break
            try:
                packet = Packet(packet_hex)
                if client.send_packet(packet):
                    send_count += 1
            except Exception:
                pass
            time.sleep(0.01)
        
        time.sleep(0.04)
        
        elapsed = int(time.time() - start_time)
        remaining = int(end_time - time.time())
        if elapsed % 60 == 0:
            print(f"[*] 已发送 {send_count} 个封包，剩余 {remaining // 60} 分钟")
    
    print(f"[+] 刷取完成，共发送 {send_count} 个封包")
    return True


def load_config():
    config_json = os.environ.get("DDD_CONFIG")
    if config_json:
        return json.loads(config_json)
    
    config_file = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    
    return None


def process_account(account):
    global serial_num, user_id, session_bytes
    serial_num, user_id, session_bytes = 0, 0, bytes()
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    
    username = account.get("username", "")
    password = account.get("password", "")
    server = account.get("server", 100)
    duration = account.get("duration_minutes", 60)
    
    if not username or not password:
        print("[-] 账号密码未配置")
        return False
    
    print(f"\n[*] 账号: {username} | 服务器: {server} | 时长: {duration}分钟")
    
    client = Client()
    
    try:
        if not client.connect_login_server():
            return False
        
        if not client.login_server_auth(username, password, server):
            return False
        
        if not client.connect_main_server(server):
            return False
        
        if not client.main_server_login(server):
            return False
        
        run_ddd(client, duration)
        
        print(f"[+] 账号 {username} 完成")
        return True
        
    except Exception as e:
        print(f"[-] 账号 {username} 错误: {e}")
        return False
    finally:
        client.close()


def process_account_entry(account):
    """多进程入口"""
    success = process_account(account)
    if not success:
        raise SystemExit(1)


def main():
    config = load_config()
    if not config:
        print("[-] 未找到配置")
        return 1
    
    if isinstance(config, dict):
        accounts = [config]
    else:
        accounts = config
    
    print(f"[*] 共 {len(accounts)} 个账号，并行刷取")
    
    processes = []
    for account in accounts:
        p = Process(target=process_account_entry, args=(account,))
        p.start()
        processes.append(p)
    
    success = 0
    for p in processes:
        p.join()
        if p.exitcode == 0:
            success += 1
      
    print(f"\n{'='*40}")
    print(f"[*] 完成: {success}/{len(accounts)} 成功")
    return 0 if success == len(accounts) else 1


if __name__ == "__main__":
    sys.exit(main())
