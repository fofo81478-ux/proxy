from kivy.app import App
from kivy.uix.button import Button
import threading
import Tcp

class ProxyApp(App):
    def build(self):
        btn = Button(
            text="تشغيل البروكسي (TCP Proxy)",
            font_size=24
        )
        btn.bind(on_press=self.start_proxy)
        return btn

    def start_proxy(self, instance):
        # تشغيل البروكسي في خيط منفصل حتى لا تتجمد الواجهة
        threading.Thread(target=Tcp.main, daemon=True).start()

if __name__ == "__main__":
    ProxyApp().run()
