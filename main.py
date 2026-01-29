import os
folders = ['input', 'output', 'logs']
for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)
files = [
    os.path.join('input', 'cookies.txt'),
    os.path.join('input', 'proxies.txt'),
    os.path.join('output', 'results.txt'),
    os.path.join('logs', 'summary.txt')
]
for file_path in files:
    folder = os.path.dirname(file_path)
    if not os.path.exists(folder):
        os.makedirs(folder)
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            pass

import time
import hashlib
import base64
import json
import random
from random import choice, shuffle, uniform, randint
from threading import Thread, Lock
from typing import Dict, Tuple, List, Optional
from curl_cffi import Session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from colorama import Fore, Style


class AuthTokenGenerator:
    @staticmethod
    def _to_bytes(text: str) -> bytes:
        return text.encode('utf-8')

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode('ascii')

    @staticmethod
    def generate_token(payload: str, endpoint: str, http_method: str) -> str:
        payload_bytes = payload.encode('utf-8')
        hash_digest = hashlib.sha256(payload_bytes).digest()
        encoded_hash = AuthTokenGenerator._b64_encode(hash_digest)

        current_time = str(int(time.time()))
        key_pair = ec.generate_private_key(ec.SECP256R1(), default_backend())

        sig_data = f"{encoded_hash}|{current_time}|{endpoint}|{http_method.upper()}"
        sig_bytes = key_pair.sign(
            AuthTokenGenerator._to_bytes(sig_data),
            ec.ECDSA(hashes.SHA256())
        )
        r_val, s_val = decode_dss_signature(sig_bytes)
        sig_raw = r_val.to_bytes(32, 'big') + s_val.to_bytes(32, 'big')
        encoded_sig1 = AuthTokenGenerator._b64_encode(sig_raw)

        path_suffix = endpoint.split('.com')[1] if '.com' in endpoint else endpoint
        sig_data2 = f"|{current_time}|{path_suffix}|{http_method.upper()}"
        sig_bytes2 = key_pair.sign(
            AuthTokenGenerator._to_bytes(sig_data2),
            ec.ECDSA(hashes.SHA256())
        )
        r_val2, s_val2 = decode_dss_signature(sig_bytes2)
        sig_raw2 = r_val2.to_bytes(32, 'big') + s_val2.to_bytes(32, 'big')
        encoded_sig2 = AuthTokenGenerator._b64_encode(sig_raw2)

        return f"v1|{encoded_hash}|{current_time}|{encoded_sig1}|{encoded_sig2}"


class RobloxClient:
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    ]

    def __init__(self):
        self.token_gen = AuthTokenGenerator()

    def _get_headers(self) -> Dict[str, str]:
        return {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'origin': 'https://www.roblox.com',
            'referer': 'https://www.roblox.com/',
            'user-agent': choice(self.USER_AGENTS),
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
        }

    def _setup_session_cookies(self, auth_cookie: str, session: Session) -> None:
        session.allow_redirects = True
        session.cookies.set(".ROBLOSECURITY", auth_cookie, ".roblox.com", "/", secure=True)
        response = session.get("https://roblox.com", timeout=10)
        session.cookies.update(response.cookies)
        time.sleep(uniform(0.5, 1.5))

    def _obtain_csrf_token(self, session: Session) -> Optional[str]:
        endpoint = "https://friends.roblox.com/v1/users/1/follow"
        try:
            response = session.post(endpoint, timeout=10)
            csrf_token = response.headers.get("x-csrf-token")
            if csrf_token:
                session.headers.update({"x-csrf-token": csrf_token})
                return csrf_token
        except Exception as e:
            pass
        return None

    def _parse_error_reason(self, response_text: str, status_code: int) -> str:
        if not response_text:
            if status_code == 403:
                return "Forbidden - Possible rate limit or captcha"
            elif status_code == 401:
                return "Unauthorized - Invalid cookie"
            elif status_code == 404:
                return "User not found"
            elif status_code == 429:
                return "Rate limited"
            else:
                return f"HTTP {status_code} error"
        
        try:
            error_data = json.loads(response_text)
            if isinstance(error_data, dict):
                if "errors" in error_data and error_data["errors"]:
                    error_msg = error_data["errors"][0].get("message", "")
                    if error_msg:
                        return error_msg[:60]
                if "message" in error_data:
                    return error_data["message"][:60]
                if "error" in error_data:
                    return str(error_data["error"])[:60]
        except:
            pass
        
        response_lower = response_text.lower()
        if "captcha" in response_lower or "challenge" in response_lower:
            return "Captcha required"
        elif "rate limit" in response_lower or "too many" in response_lower:
            return "Rate limited"
        elif "unauthorized" in response_lower or "invalid" in response_lower:
            return "Invalid authentication"
        elif "not found" in response_lower:
            return "User not found"
        elif "already" in response_lower:
            return "Already following user"
        
        return response_text[:60] if len(response_text) > 60 else response_text

    def execute_follow(self, auth_cookie: str, proxy_addr: str, target_user_id: str) -> Tuple[str, bool, str, int]:
        client_session = Session(
            impersonate="safari",
            default_headers=True,
            proxy=proxy_addr,
            timeout=15
        )

        client_session.headers.update(self._get_headers())

        api_endpoint = f"https://friends.roblox.com/v1/users/{target_user_id}/follow"
        auth_token = self.token_gen.generate_token("", api_endpoint, "post")
        client_session.headers.update({"x-bound-auth-token": auth_token})

        try:
            self._setup_session_cookies(auth_cookie, client_session)
            
            csrf = self._obtain_csrf_token(client_session)
            if not csrf:
                client_session.close()
                return ("CSRF token retrieval failed", False, "", 0)

            time.sleep(uniform(0.3, 0.8))

            response = client_session.post(api_endpoint, timeout=15)
            status_code = response.status_code
            response_text = response.text
            client_session.close()

            if status_code == 200:
                return ("SUCCESS", True, response_text, status_code)
            else:
                error_reason = self._parse_error_reason(response_text, status_code)
                return (error_reason, False, response_text, status_code)
        except Exception as e:
            try:
                client_session.close()
            except:
                pass
            error_msg = str(e)
            if "timeout" in error_msg.lower():
                return ("Connection timeout", False, "", 0)
            elif "proxy" in error_msg.lower():
                return ("Proxy connection failed", False, "", 0)
            else:
                return (f"Network error: {error_msg[:40]}", False, "", 0)


class PerformanceTracker:
    def __init__(self):
        self.lock = Lock()
        self.completed = 0
        self.failed = 0
        self.start_time = time.time()

    def increment_success(self):
        with self.lock:
            self.completed += 1

    def increment_failure(self):
        with self.lock:
            self.failed += 1

    def get_rate(self) -> float:
        elapsed = time.time() - self.start_time
        minutes = elapsed / 60.0
        if minutes == 0:
            return 0.0
        return round(self.completed / minutes, 2)

    def get_stats(self) -> Tuple[int, int, float]:
        with self.lock:
            return self.completed, self.failed, self.get_rate()


def load_resources() -> Tuple[List[str], List[str]]:
    try:
        with open("input/proxies.txt", "r", encoding="utf-8") as f:
            proxy_list = [p.strip() for p in f.read().splitlines() if p.strip()]
    except FileNotFoundError:
        proxy_list = []
    
    try:
        with open("input/cookies.txt", "r", encoding="utf-8") as f:
            cookie_list = [c.strip() for c in f.read().splitlines() if c.strip()]
    except FileNotFoundError:
        cookie_list = []

    shuffle(cookie_list)
    return proxy_list, cookie_list


def distribute_items(items: List, num_workers: int) -> List[List]:
    if num_workers <= 0:
        return [items]
    
    chunk_size = len(items) / num_workers
    result = []
    current_pos = 0.0
    
    while current_pos < len(items):
        end_pos = int(current_pos + chunk_size)
        result.append(items[int(current_pos):end_pos])
        current_pos += chunk_size
    
    return result


def process_batch(cookie_batch: List[str], user_id: str, tracker: PerformanceTracker, proxy_pool: List[str]):
    client = RobloxClient()
    
    for auth_cookie in cookie_batch:
        max_retries = 3
        retry_count = 0
        succeeded = False
        
        while retry_count < max_retries and not succeeded:
            try:
                selected_proxy = choice(proxy_pool) if proxy_pool else None
                request_start = time.time()
                
                result_msg, success, response_data, status_code = client.execute_follow(
                    auth_cookie, selected_proxy, user_id
                )
                
                request_time = round(time.time() - request_start, 2)
                
                if success:
                    tracker.increment_success()
                    completed, failed, rate = tracker.get_stats()
                    print(f"{Fore.GREEN}Success{Style.RESET_ALL} | User: {user_id} | Time: {request_time}s | Done: {completed} | {rate}/min")
                    succeeded = True
                else:
                    retry_count += 1
                    tracker.increment_failure()
                    completed, failed, rate = tracker.get_stats()
                    status_info = f"{status_code}" if status_code > 0 else "N/A"
                    print(f"{Fore.RED}Failed{Style.RESET_ALL} | User: {user_id} | Try {retry_count}/{max_retries} | Status: {status_info} | Reason: {result_msg} | Failed: {failed} | {rate}/min")
                    
                    if retry_count < max_retries:
                        delay = uniform(1.0, 2.5) * retry_count
                        time.sleep(delay)
                        
            except Exception as e:
                retry_count += 1
                tracker.increment_failure()
                completed, failed, rate = tracker.get_stats()
                error_msg = str(e)[:40]
                print(f"{Fore.RED}Error{Style.RESET_ALL} | User: {user_id} | Try {retry_count}/{max_retries} | {error_msg} | Failed: {failed} | {rate}/min")
                if retry_count < max_retries:
                    time.sleep(uniform(0.5, 1.5))
        
        if not succeeded:
            time.sleep(uniform(0.2, 0.6))


def main():
    proxy_pool, cookie_pool = load_resources()
    
    if not cookie_pool:
        print("No cookies found")
        return
    
    try:
        thread_count = int(input("Enter thread count: "))
        target_user = input("Enter user id: ")
    except (ValueError, KeyboardInterrupt):
        return
    
    if thread_count <= 0:
        thread_count = 1
    
    print(f"\nStarting {thread_count} threads with {len(cookie_pool)} cookies\n")
    
    tracker = PerformanceTracker()
    batches = distribute_items(cookie_pool, thread_count)
    worker_threads = []
    
    for batch in batches:
        if batch:
            thread = Thread(
                target=process_batch,
                args=(batch, target_user, tracker, proxy_pool)
            )
            worker_threads.append(thread)
            thread.start()
            time.sleep(uniform(0.1, 0.3))
    
    for thread in worker_threads:
        thread.join()
    
    final_completed, final_failed, final_rate = tracker.get_stats()
    total_attempts = final_completed + final_failed
    success_rate = (final_completed / total_attempts * 100) if total_attempts > 0 else 0
    
    print(f"\nDone | Success: {final_completed} | Failed: {final_failed} | Total: {total_attempts} | Rate: {success_rate:.1f}% | {final_rate}/min")


import customtkinter as ctk
import threading
from tkinter import messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

PALETTE = {
    "bg": "#000000",
    "panel": "#0a0a0a",
    "panel_alt": "#111111",
    "panel_soft": "#181818",
    "panel_soft_alt": "#222222",
    "text": "#f2f2f2",
    "text_muted": "#9aa0a6",
    "text_bright": "#ffffff",
    "accent": "#2d7dff",
    "accent_hover": "#1a6eff",
    "success": "#28a745",
    "success_hover": "#218838",
    "danger": "#dc3545",
    "danger_hover": "#c82333",
    "warning": "#ffc107",
    "warning_hover": "#e0a800",
    "info": "#17a2b8",
    "info_hover": "#138496",
    "border": "#2a2a2a"
}


import webbrowser

class FollowBotGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Roblox Follow Bot")
        self.geometry("1000x650")
        self.minsize(900, 500)
        self.configure(fg_color=PALETTE["bg"])

        self.lang = "en"
        self.cookies = []
        self.proxies = []
        self.is_running = False
        self.threads = []
        self.stop_event = threading.Event()

        self.translations = {
            "en": {
                "user_id": "Target User ID:",
                "user_id_placeholder": "e.g. 123456789",
                "threads": "Threads:",
                "start": "START BOT",
                "stop": "STOP",
                "logs": "LOGS",
                "about": "About",
                "check_cookies": "Check Cookies",
                "check_proxies": "Check Proxies",
                "about_text": "Developed by Gon\nGitHub: 00ie\nTelegram: feicoes\nDiscord: tlwm\nServer: discord.gg/BYMwReFWZq",
                "no_cookies": "No cookies found.",
                "no_proxies": "No proxies found.",
                "cookies_loaded": "{count} cookies loaded.",
                "proxies_loaded": "{count} proxies loaded.",
                "proxy_ok": "Proxy {proxy}... working ({ip})",
                "proxy_fail": "Proxy {proxy}... failed",
                "invalid_user": "Enter a valid User ID!",
                "starting": "Starting bot for User ID: {user_id} with {threads} threads.",
                "finished": "\nFinished | Success: {success} | Failed: {failed} | Total: {total} | Rate: {rate:.1f}% | {per_min}/min",
                "stopped": "Bot stopped by user.",
            },
            "pt": {
                "user_id": "User ID Alvo:",
                "user_id_placeholder": "Ex: 123456789",
                "threads": "Número de Threads:",
                "start": "INICIAR BOT",
                "stop": "PARAR",
                "logs": "LOGS",
                "about": "Sobre",
                "check_cookies": "Verificar Cookies",
                "check_proxies": "Verificar Proxies",
                "about_text": "Desenvolvido por Gon\nGitHub: 00ie\nTelegram: feicoes\nDiscord: tlwm\nServidor: discord.gg/BYMwReFWZq",
                "no_cookies": "Nenhum cookie encontrado.",
                "no_proxies": "Nenhum proxy encontrado.",
                "cookies_loaded": "{count} cookies carregados.",
                "proxies_loaded": "{count} proxies carregados.",
                "proxy_ok": "Proxy {proxy}... funcionando ({ip})",
                "proxy_fail": "Proxy {proxy}... falhou",
                "invalid_user": "Digite um User ID válido!",
                "starting": "Iniciando bot para User ID: {user_id} com {threads} threads.",
                "finished": "\nFinalizado | Sucesso: {success} | Falha: {failed} | Total: {total} | Taxa: {rate:.1f}% | {per_min}/min",
                "stopped": "Bot parado pelo usuário.",
            }
        }

        self.setup_ui()

    def t(self, key, **kwargs):
        txt = self.translations[self.lang][key]
        return txt.format(**kwargs) if kwargs else txt

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.top_frame = ctk.CTkFrame(self, fg_color=PALETTE["panel"], height=60, corner_radius=0)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.top_frame.grid_columnconfigure(1, weight=1)

        self.title_label = ctk.CTkLabel(
            self.top_frame,
            text="ROBLOX FOLLOW BOT",
            font=("Segoe UI", 24, "bold"),
            text_color=PALETTE["accent"]
        )
        self.title_label.grid(row=0, column=0, padx=30, pady=15, sticky="w")

        self.status_label = ctk.CTkLabel(
            self.top_frame,
            text="Ready",
            font=("Segoe UI", 12),
            text_color=PALETTE["text_muted"]
        )
        self.status_label.grid(row=0, column=1, padx=20, pady=15, sticky="e")

        self.sidebar = ctk.CTkFrame(self, fg_color=PALETTE["panel_alt"], width=260, corner_radius=0)
        self.sidebar.grid(row=1, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.lang_btn = ctk.CTkOptionMenu(self.sidebar, values=["English", "Português"], command=self.set_lang)
        self.lang_btn.set("English")
        self.lang_btn.pack(pady=(10, 10), padx=20, fill="x")

        self.user_id_label = ctk.CTkLabel(
            self.sidebar,
            text=self.t("user_id"),
            font=("Segoe UI", 12),
            text_color=PALETTE["text_muted"]
        )
        self.user_id_label.pack(pady=(10, 5), padx=20, anchor="w")

        self.user_id_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text=self.t("user_id_placeholder"),
            height=35,
            fg_color=PALETTE["panel_soft"],
            border_color=PALETTE["border"],
            text_color=PALETTE["text"]
        )
        self.user_id_entry.pack(pady=(0, 15), padx=20, fill="x")

        self.threads_label = ctk.CTkLabel(
            self.sidebar,
            text=self.t("threads"),
            font=("Segoe UI", 12),
            text_color=PALETTE["text_muted"]
        )
        self.threads_label.pack(pady=(10, 5), padx=20, anchor="w")

        self.threads_slider = ctk.CTkSlider(
            self.sidebar,
            from_=1,
            to=20,
            number_of_steps=19,
            height=20,
            button_color=PALETTE["accent"],
            progress_color=PALETTE["accent_hover"],
            fg_color=PALETTE["panel_soft"]
        )
        self.threads_slider.set(5)
        self.threads_slider.pack(pady=(0, 5), padx=20, fill="x")

        self.check_cookies_btn = ctk.CTkButton(
            self.sidebar,
            text=self.t("check_cookies"),
            command=self.check_cookies,
            height=35,
            fg_color=PALETTE["info"],
            hover_color=PALETTE["info_hover"],
            font=("Segoe UI", 12)
        )
        self.check_cookies_btn.pack(pady=(10, 5), padx=20, fill="x")

        self.check_proxies_btn = ctk.CTkButton(
            self.sidebar,
            text=self.t("check_proxies"),
            command=self.check_proxies,
            height=35,
            fg_color=PALETTE["info"],
            hover_color=PALETTE["info_hover"],
            font=("Segoe UI", 12)
        )
        self.check_proxies_btn.pack(pady=(0, 10), padx=20, fill="x")

        self.start_btn = ctk.CTkButton(
            self.sidebar,
            text=self.t("start"),
            command=self.start_bot,
            height=40,
            fg_color=PALETTE["success"],
            hover_color=PALETTE["success_hover"],
            font=("Segoe UI", 14, "bold")
        )
        self.start_btn.pack(pady=(10, 10), padx=20, fill="x")

        self.stop_btn = ctk.CTkButton(
            self.sidebar,
            text=self.t("stop"),
            command=self.stop_bot,
            height=35,
            fg_color=PALETTE["danger"],
            hover_color=PALETTE["danger_hover"],
            font=("Segoe UI", 12),
            state="disabled"
        )
        self.stop_btn.pack(pady=5, padx=20, fill="x")

        self.tabs = ctk.CTkTabview(self.sidebar)
        self.tabs.pack(padx=10, pady=(10, 10), fill="both", expand=True)
        self.config_tab = self.tabs.add("Config")
        self.about_tab = self.tabs.add("About")

        about_scroll = ctk.CTkScrollableFrame(self.about_tab, fg_color=PALETTE["panel_soft"], corner_radius=10)
        about_scroll.pack(pady=(10, 20), padx=10, fill="both", expand=True)

        self.about_github = ctk.CTkLabel(
            about_scroll,
            text="GitHub: 00ie",
            font=("Segoe UI", 11, "underline"),
            text_color=PALETTE["accent"],
            anchor="w",
            justify="left"
        )
        self.about_github.pack(pady=2, padx=10, anchor="w", fill="x")
        self.about_github.bind("<Button-1>", lambda _e: webbrowser.open_new_tab("https://github.com/00ie"))

        self.about_telegram = ctk.CTkLabel(
            about_scroll,
            text="Telegram: feicoes",
            font=("Segoe UI", 11, "underline"),
            text_color=PALETTE["accent"],
            anchor="w",
            justify="left"
        )
        self.about_telegram.pack(pady=2, padx=10, anchor="w", fill="x")
        self.about_telegram.bind("<Button-1>", lambda _e: webbrowser.open_new_tab("https://t.me/feicoes"))

        self.about_discord = ctk.CTkLabel(
            about_scroll,
            text="Discord: tlwm",
            font=("Segoe UI", 11, "underline"),
            text_color=PALETTE["accent"],
            anchor="w",
            justify="left"
        )
        self.about_discord.pack(pady=2, padx=10, anchor="w", fill="x")
        self.about_discord.bind("<Button-1>", lambda _e: webbrowser.open_new_tab("https://discord.com"))

        self.about_server = ctk.CTkLabel(
            about_scroll,
            text="Server: discord.gg/BYMwReFWZq",
            font=("Segoe UI", 11, "underline"),
            text_color=PALETTE["accent"],
            anchor="w",
            justify="left"
        )
        self.about_server.pack(pady=(2, 10), padx=10, anchor="w", fill="x")
        self.about_server.bind("<Button-1>", lambda _e: webbrowser.open_new_tab("https://discord.gg/BYMwReFWZq"))

        self.about_footer = ctk.CTkLabel(
            about_scroll,
            text="Developed by Gon",
            font=("Segoe UI", 10),
            text_color=PALETTE["text_muted"],
            anchor="w",
            justify="left"
        )
        self.about_footer.pack(pady=(10, 0), padx=10, anchor="w", fill="x")

        self.main_area = ctk.CTkFrame(self, fg_color=PALETTE["panel"], corner_radius=0)
        self.main_area.grid(row=1, column=1, sticky="nsew", padx=0, pady=0)
        self.main_area.grid_columnconfigure(0, weight=1)
        self.main_area.grid_rowconfigure(1, weight=1)

        self.logs_label = ctk.CTkLabel(
            self.main_area,
            text=self.t("logs"),
            font=("Segoe UI", 14, "bold"),
            text_color=PALETTE["text"]
        )
        self.logs_label.pack(pady=(10, 5), padx=10, anchor="w")

        self.logs_text = ctk.CTkTextbox(
            self.main_area,
            fg_color=PALETTE["panel_alt"],
            text_color=PALETTE["text"],
            border_color=PALETTE["border"],
            border_width=1,
            font=("Consolas", 10)
        )
        self.logs_text.pack(padx=10, pady=(0, 10), fill="both", expand=True)

    def set_lang(self, value):
        self.lang = "en" if value == "English" else "pt"
        self.user_id_label.configure(text=self.t("user_id"))
        self.user_id_entry.configure(placeholder_text=self.t("user_id_placeholder"))
        self.threads_label.configure(text=self.t("threads"))
        self.start_btn.configure(text=self.t("start"))
        self.stop_btn.configure(text=self.t("stop"))
        self.check_cookies_btn.configure(text=self.t("check_cookies"))
        self.check_proxies_btn.configure(text=self.t("check_proxies"))
        self.logs_label.configure(text=self.t("logs"))
        self.tabs.set("About")

    def log_message(self, message: str, color: str = "normal"):
        self.logs_text.configure(state="normal")
        self.logs_text.insert("end", message + "\n")
        self.logs_text.see("end")
        self.logs_text.configure(state="disabled")
        self.update_idletasks()

    def check_cookies(self):
        try:
            with open("input/cookies.txt", "r", encoding="utf-8") as f:
                self.cookies = [c.strip() for c in f.read().splitlines() if c.strip()]
        except FileNotFoundError:
            self.cookies = []
        if not self.cookies:
            self.log_message(self.t("no_cookies"), "error")
        else:
            self.log_message(self.t("cookies_loaded", count=len(self.cookies)), "success")

    def check_proxies(self):
        try:
            with open("input/proxies.txt", "r", encoding="utf-8") as f:
                self.proxies = [p.strip() for p in f.read().splitlines() if p.strip()]
        except FileNotFoundError:
            self.proxies = []
        if not self.proxies:
            self.log_message(self.t("no_proxies"), "info")
        else:
            self.log_message(self.t("proxies_loaded", count=len(self.proxies)), "success")
            import requests
            import random
            test_proxies = random.sample(self.proxies, min(3, len(self.proxies)))
            for proxy in test_proxies:
                try:
                    response = requests.get(
                        "http://httpbin.org/ip",
                        proxies={"http": proxy, "https": proxy},
                        timeout=5
                    )
                    if response.status_code == 200:
                        ip_info = response.json().get('origin', 'Unknown')
                        self.log_message(self.t("proxy_ok", proxy=proxy[:30], ip=ip_info), "success")
                    else:
                        self.log_message(self.t("proxy_fail", proxy=proxy[:30]), "warning")
                except:
                    self.log_message(self.t("proxy_fail", proxy=proxy[:30]), "error")

    def start_bot(self):
        if self.is_running:
            return
        user_id = self.user_id_entry.get().strip()
        if not user_id or not user_id.isdigit():
            messagebox.showwarning("Warning", self.t("invalid_user"))
            return
        thread_count = int(self.threads_slider.get())
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.is_running = True
        self.stop_event.clear()
        self.logs_text.configure(state="normal")
        self.logs_text.delete("1.0", "end")
        self.logs_text.configure(state="disabled")
        self.log_message(self.t("starting", user_id=user_id, threads=thread_count))
        threading.Thread(target=self.run_bot, args=(user_id, thread_count), daemon=True).start()

    def run_bot(self, user_id, thread_count):
        try:
            proxy_pool, cookie_pool = load_resources()
            if not cookie_pool:
                self.log_message(self.t("no_cookies"), "error")
                self.is_running = False
                self.start_btn.configure(state="normal")
                self.stop_btn.configure(state="disabled")
                return
            tracker = PerformanceTracker()
            batches = distribute_items(cookie_pool, thread_count)
            worker_threads = []
            for batch in batches:
                if batch:
                    thread = Thread(
                        target=process_batch,
                        args=(batch, user_id, tracker, proxy_pool)
                    )
                    worker_threads.append(thread)
                    thread.start()
                    time.sleep(uniform(0.1, 0.3))
            for thread in worker_threads:
                thread.join()
            final_completed, final_failed, final_rate = tracker.get_stats()
            total_attempts = final_completed + final_failed
            success_rate = (final_completed / total_attempts * 100) if total_attempts > 0 else 0
            self.log_message(self.t("finished", success=final_completed, failed=final_failed, total=total_attempts, rate=success_rate, per_min=final_rate))
        except Exception as e:
            self.log_message(f"Error: {str(e)}", "error")
        self.is_running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def stop_bot(self):
        if not self.is_running:
            return
        self.stop_event.set()
        self.is_running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.log_message(self.t("stopped"), "warning")


if __name__ == "__main__":
    app = FollowBotGUI()
    app.mainloop()