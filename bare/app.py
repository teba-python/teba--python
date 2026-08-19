
import json
import os
import time
import webbrowser
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from plyer import notification
import requests

# =========================
# Settings
# =========================

API_KEY = "ضعي_مفتاح_API_الخاص_بك_هنا"
CONFIG_FILE = "app_config.json"
MY_INSTAGRAM = "https://instagram.com/your_username"
VT_URL = "https://www.virustotal.com/api/v3/urls"

# =========================
# Logic
# =========================

def check_three_days_passed():
    current_time = time.time()
    three_days = 3 * 24 * 60 * 60
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            last_sent = data.get("last_notification_time", 0)
            if current_time - last_sent >= three_days:
                save_current_time(current_time)
                return True
            return False
        except:
            save_current_time(current_time)
            return False
    else:
        save_current_time(current_time)
        return False

def save_current_time(current_time):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"last_notification_time": current_time}, f)

def show_developer_contact_popup():
    layout = BoxLayout(orientation="vertical", padding=15, spacing=10)
    layout.add_widget(Label(text="Thanks for using our app!\nWould you like to contact the developer?"))
    btn_layout = BoxLayout(spacing=10, size_hint_y=0.4)
    btn_yes = Button(text="Yes")
    btn_no = Button(text="No")
    btn_layout.add_widget(btn_yes)
    btn_layout.add_widget(btn_no)
    layout.add_widget(btn_layout)
    popup = Popup(title="Developer Contact", content=layout, size_hint=(0.85, 0.4), auto_dismiss=False)
    btn_yes.bind(on_release=lambda x: [popup.dismiss(), webbrowser.open(MY_INSTAGRAM)])
    btn_no.bind(on_release=lambda x: [popup.dismiss(), notification.notify(title="Link Checker", message="Have a nice day!", app_name="Link Checker", timeout=5)])
    popup.open()

def scan_url(url):
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.post(VT_URL, headers=headers, data={"url": url}, timeout=30)
        if response.status_code != 200:
            return {"success": False, "message": f"Failed. Error code: {response.status_code}"}
        data = response.json()
        analysis_id = data["data"]["id"]
        analysis_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id
        for _ in range(10):
            time.sleep(2)
            result = requests.get(analysis_url, headers=headers, timeout=30)
            if result.status_code == 200:
                result_data = result.json()
                attributes = result_data["data"]["attributes"]
                if attributes.get("status") == "completed":
                    stats = attributes.get("stats", {})
                    return {"success": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}
        return {"success": False, "message": "Scan took too long."}
    except:
        return {"success": False, "message": "Connection error."}

# =========================
# Main App
# =========================

class LinkScannerApp(App):
    def build(self):
        main_layout = BoxLayout(orientation="vertical", padding=20, spacing=15)
        main_layout.add_widget(Label(text="🛡️ Link Checker", font_size=28, size_hint_y=None, height=60))
        main_layout.add_widget(Label(text="Paste the URL to scan below:", font_size=17, size_hint_y=None, height=60))
        self.url_input = TextInput(hint_text="https://example.com", multiline=False, size_hint_y=None, height=55)
        main_layout.add_widget(self.url_input)
        self.scan_button = Button(text="🔍 Scan URL", size_hint_y=None, height=60)
        self.scan_button.bind(on_release=self.start_scan)
        main_layout.add_widget(self.scan_button)
        self.result_label = Label(text="Waiting for input...", font_size=18)
        main_layout.add_widget(self.result_label)
        if check_three_days_passed():
            Clock.schedule_once(lambda dt: show_developer_contact_popup())
        return main_layout

    def start_scan(self, instance):
        url = self.url_input.text.strip()
        if not url:
            self.result_label.text = "⚠️ Please enter a URL."
            return
        self.scan_button.disabled = True
        self.scan_button.text = "⏳ Scanning..."
        threading.Thread(target=self.run_scan, args=(url,)).start()

    def run_scan(self, url):
        result = scan_url(url)
        Clock.schedule_once(lambda dt: self.show_result(result))

    def show_result(self, result):
        self.scan_button.disabled = False
        self.scan_button.text = "🔍 Scan URL"
        if not result["success"]:
            self.result_label.text = "❌ Error: " + result["message"]
            return
        self.result_label.text = f"✅ Scan Complete!\nMalicious: {result['malicious']}\nSuspicious: {result['suspicious']}\nHarmless: {result['harmless']}"

if __name__ == "__main__":
    LinkScannerApp().run()