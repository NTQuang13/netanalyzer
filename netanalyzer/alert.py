"""Gửi cảnh báo: log + file JSONL + Telegram (tuỳ chọn, qua biến môi trường TG_TOKEN / TG_CHAT)."""
import json
import logging
import os

import requests

log = logging.getLogger("nta.alert")


def notify(alert, jsonl=None, telegram=True):
    log.warning("ALERT [%s] %s: %s", alert["severity"], alert["type"], alert["detail"])
    if jsonl:
        with open(jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    token, chat = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT")
    if telegram and token and chat:
        try:
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=5,
                          json={"chat_id": chat,
                                "text": f"[{alert['severity'].upper()}] {alert['type']}\n{alert['detail']}"})
        except requests.RequestException as e:   # không để lỗi mạng làm sập analyzer
            log.error("Telegram lỗi: %s", e)
