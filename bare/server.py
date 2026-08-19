
from flask import Flask, request, render_template
import requests
import os
from dotenv import load_dotenv
import time

# 1. تحميل المتغيرات السرية من ملف .env
load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

# قاموس محلي لتخزين عدد الطلبات لكل IP مع وقت البداية
ip_requests = {}

@app.route('/', methods=['GET', 'POST'])
def home():
    # 2. تطبيق نظام Rate Limiting محلياً (10 طلبات لكل دقيقة لكل IP)
    client_ip = request.remote_addr
    current_time = time.time()
    
    if client_ip not in ip_requests:
        ip_requests[client_ip] = {"count": 1, "start_time": current_time}
    else:
        data = ip_requests[client_ip]
        if current_time - data["start_time"] > 60:
            ip_requests[client_ip] = {"count": 1, "start_time": current_time}
        else:
            data["count"] += 1
            if data["count"] > 10:
                return render_template('index.html', result=False, error="تم تجاوز عدد محاولات الفحص المسموح بها (10 طلبات في الدقيقة)، يرجى المحاولة بعد قليل.")

    if request.method == 'POST':
        url_input = request.form.get('url')
        
        # 3. التحقق الأساسي وحماية الـ SSRF
        if not url_input or len(url_input.strip()) < 5 or '.' not in url_input or ' ' in url_input:
            return render_template('index.html', result=False, error="خطأ: يرجى إدخال رابط صحيح (مثل https://example.com).")
            
        forbidden_words = ["localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10."]
        if any(word in url_input.lower() for word in forbidden_words):
            return render_template('index.html', result=False, error="تنبيه أمني: لا يمكن فحص العناوين الداخلية أو المحلية لأسباب تتعلق بالأمان.")

        headers = {"x-apikey": API_KEY}
        payload = {"url": url_input}
        
        # 4. الاتصال مع معالجة الأخطاء الآمنة (بدون تسريب مسارات أو معلومات حساسة)
        try:
            response = requests.post(VT_URL, headers=headers, data=payload, timeout=10)
            
            # التحقق إذا كان مفتاح الـ API غير صالح أو انتهت صلاحيته
            if response.status_code == 401:
                return render_template('index.html', result=False, error="عذراً، هناك مشكلة في صلاحية مفتاح الربط مع خدمة الفحص.")
            
            json_response = response.json()
            
            if "data" in json_response:
                analysis_id = json_response["data"]["id"]
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                
                report_response = requests.get(analysis_url, headers=headers, timeout=10)
                report_json = report_response.json()
                stats = report_json.get("data", {}).get("attributes", {}).get("stats", {})
                
                return render_template('index.html', result=True, url=url_input, harmless=stats.get("harmless", 0), malicious=stats.get("malicious", 0))
            else:
                # رسالة عامة للمستخدم بدلاً من كشف تفاصيل استجابة الـ API التقنية
                return render_template('index.html', result=False, error="تعذر إتمام عملية فحص الرابط حالياً، يرجى التأكد من صحة الرابط والمحاولة لاحقاً.")
                
        except requests.exceptions.Timeout:
            return render_template('index.html', result=False, error="انتهت مهلة الانتظار أثناء الاتصال بخدمة الفحص، يرجى المحاولة لاحقاً.")
        except requests.exceptions.RequestException:
            # معالجة آمنة لخطوط الاتصال والشبكة دون إظهار أي Traceback للمستخدم
            return render_template('index.html', result=False, error="حدث خطأ أثناء الاتصال بالخدمة، يرجى التحقق من شبكة الإنترنت والمحاولة مرة أخرى.")
        except Exception:
            # خطأ عام واحتياطي يمنع ظهور أي تفاصيل برمجية أو مسارات على الشاشة
            return render_template('index.html', result=False, error="حدث خطأ غير متوقع في النظام، يرجى المحاولة في وقت لاحق.")
        
    return render_template('index.html', result=False)

if __name__ == '__main__':
    # إيقاف وضع الـ debug لتجنب ظهور صفحة الأخطاء التفاعلية للعامة
  import os
port=int(os.environ.get('PORT',5000))
app.run(host='0.0.0.0',port=port)