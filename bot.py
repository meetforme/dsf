import os
import re
import io
import hmac
import math
import time
import html
import json
import base64
import hashlib
import logging
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from telegram import (
    Update,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    BotCommand,
    InputFile,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

APP_NAME = "SafeGate Research Bot"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "safegate.db"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(APP_NAME)


MAIN_KEYBOARD = ReplyKeyboardMarkup(
    [
        ["ℹ️ Информация", "🧱 Архитектура"],
        ["⚠️ Угрозы", "📜 Политика ИБ"],
        ["🔍 Проверить ввод", "🔐 Проверить секрет"],
        ["📉 Риск", "🛡 IDS"],
        ["🏢 SOC", "🎭 Demo Attack"],
        ["🔴 Red Team", "🔵 Blue Team"],
        ["👤 Профиль", "📋 Меню команд"],
    ],
    resize_keyboard=True,
)

HINT_TEXT = (
    "Подсказка:\n"
    "• /check текст — анализ подозрительного ввода\n"
    "• /verify код — безопасная проверка секрета\n"
    "• /simulate sql|xss|spam|bruteforce|admin|leak — симуляции атак\n"
    "• /risk — риск-профиль пользователя\n"
    "• /ids — состояние IDS\n"
    "• /soc — панель мониторинга\n"
    "• /admin — вход администратора\n"
)

THREATS_TEXT = (
    "Ключевые угрозы для Telegram-ботов:\n\n"
    "1. Утечка токена бота.\n"
    "2. Отсутствие разграничения прав доступа.\n"
    "3. Вредоносный ввод и инъекции.\n"
    "4. Brute force и подбор кодов доступа.\n"
    "5. Flood / spam и отказ в обслуживании.\n"
    "6. Неконтролируемое журналирование чувствительных данных.\n"
    "7. Ошибки конфигурации и небезопасное хранение секретов.\n"
    "8. Превышение полномочий администратора.\n"
)

ARCHITECTURE_TEXT = (
    "Архитектура защищённого Telegram-бота:\n\n"
    "• Telegram Client → Bot API → SafeGate Bot\n"
    "• Модуль аутентификации и разграничения доступа\n"
    "• Модуль анализа ввода и IDS-правил\n"
    "• Журнал событий и инцидентов (SQLite)\n"
    "• Модуль отчётности и аналитики\n"
    "• Подсистема уведомления администратора\n"
    "• Внешнее хранение секретов через .env\n"
)

POLICY_TEXT = (
    "Политика безопасной эксплуатации:\n\n"
    "• Не хранить токен в исходном коде\n"
    "• Ограничивать функции администратора по Telegram ID\n"
    "• Логировать инциденты, но не чувствительные данные целиком\n"
    "• Ограничивать частоту запросов\n"
    "• Использовать валидацию входных данных\n"
    "• Выполнять ротацию токенов при компрометации\n"
    "• Минимизировать собираемые данные о пользователях\n"
)

RED_TEXT = (
    "🔴 Red Team режим:\n\n"
    "Этот режим демонстрирует типовые атаки на Telegram-ботов:\n"
    "• SQL injection\n"
    "• XSS / внедрение скриптов\n"
    "• brute force\n"
    "• spam / flood\n"
    "• попытка эскалации привилегий\n"
    "• утечка токена\n"
)

BLUE_TEXT = (
    "🔵 Blue Team режим:\n\n"
    "Этот режим показывает защитные меры:\n"
    "• валидация пользовательского ввода\n"
    "• ограничение частоты запросов\n"
    "• временная блокировка\n"
    "• журналирование событий\n"
    "• honeypot-команды\n"
    "• контроль доступа администратора\n"
    "• отчётность по инцидентам\n"
)

MENU_COMMANDS_TEXT = (
    "Основные команды:\n\n"
    "/start — запуск бота\n"
    "/help — справка\n"
    "/menu — кнопочное меню\n"
    "/info — информация о боте\n"
    "/architecture — архитектура\n"
    "/threats — угрозы\n"
    "/policy — политика ИБ\n"
    "/profile — профиль пользователя\n"
    "/check текст — анализ ввода\n"
    "/verify код — проверка секрета\n"
    "/risk — риск пользователя\n"
    "/ids — статус IDS\n"
    "/soc — SOC-панель\n"
    "/simulate тип — симуляция атаки\n"
    "/demo_attack — живая демонстрация атаки\n"
    "/red — режим Red Team\n"
    "/blue — режим Blue Team\n"
    "/admin — запрос PIN для админ-входа\n"
    "/admin_login PIN — вход администратора\n"
    "/dashboard — админ-панель\n"
    "/logs — журнал событий\n"
    "/incident latest|id — инцидент\n"
    "/case latest|user <id> — форензика\n"
    "/report — текстовый отчёт\n"
    "/report_html — HTML-отчёт файлом\n"
    "/chart_attacks — график инцидентов\n"
)


def load_config():
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
    else:
        load_dotenv(override=True)

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    admin_id_raw = os.getenv("ADMIN_ID", "").strip()
    secret_code = os.getenv("SECRET_CODE", "safegate").strip()
    admin_pin = os.getenv("ADMIN_PIN", "123456").strip()

    if not bot_token:
        raise RuntimeError("Не найден BOT_TOKEN в .env")

    try:
        admin_id = int(admin_id_raw) if admin_id_raw else None
    except ValueError:
        raise RuntimeError("ADMIN_ID должен быть числом")

    return {
        "BOT_TOKEN": bot_token,
        "ADMIN_ID": admin_id,
        "SECRET_CODE_HASH": hashlib.sha256(secret_code.encode("utf-8")).hexdigest(),
        "ADMIN_PIN_HASH": hashlib.sha256(admin_pin.encode("utf-8")).hexdigest(),
        "ADMIN_PIN_PLAIN": admin_pin,
    }


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        telegram_id INTEGER PRIMARY KEY,
        username TEXT,
        first_name TEXT,
        role TEXT DEFAULT 'user',
        registered_at TEXT,
        last_seen TEXT,
        suspicious_count INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        blocked_until TEXT,
        auth_admin INTEGER DEFAULT 0,
        admin_session_until TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER,
        event_type TEXT,
        severity TEXT,
        description TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER,
        incident_type TEXT,
        severity TEXT,
        details TEXT,
        action_taken TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics (
        key TEXT PRIMARY KEY,
        value INTEGER DEFAULT 0
    )
    """)

    for metric in [
        "messages_total",
        "checks_total",
        "incidents_total",
        "blocked_total",
        "simulations_total",
        "honeypot_total",
        "auth_fail_total",
    ]:
        cur.execute("INSERT OR IGNORE INTO metrics(key, value) VALUES (?, 0)", (metric,))

    conn.commit()
    conn.close()


def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds")


def parse_iso(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def update_metric(key: str, delta: int = 1):
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE metrics SET value = COALESCE(value, 0) + ? WHERE key = ?", (delta, key))
    conn.commit()
    conn.close()


def get_metric(key: str) -> int:
    conn = db()
    cur = conn.cursor()
    row = cur.execute("SELECT value FROM metrics WHERE key = ?", (key,)).fetchone()
    conn.close()
    return int(row["value"]) if row else 0


def register_user(update: Update):
    user = update.effective_user
    if not user:
        return
    conn = db()
    cur = conn.cursor()
    existing = cur.execute(
        "SELECT telegram_id FROM users WHERE telegram_id = ?",
        (user.id,),
    ).fetchone()

    if existing:
        cur.execute(
            """
            UPDATE users
            SET username = ?, first_name = ?, last_seen = ?
            WHERE telegram_id = ?
            """,
            (user.username, user.first_name, now_iso(), user.id),
        )
    else:
        cur.execute(
            """
            INSERT INTO users(
                telegram_id, username, first_name, registered_at, last_seen
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (user.id, user.username, user.first_name, now_iso(), now_iso()),
        )

    conn.commit()
    conn.close()


def log_event(telegram_id: int | None, event_type: str, severity: str, description: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events(telegram_id, event_type, severity, description, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (telegram_id, event_type, severity, description, now_iso()),
    )
    conn.commit()
    conn.close()


def create_incident(telegram_id: int | None, incident_type: str, severity: str, details: str, action_taken: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO incidents(telegram_id, incident_type, severity, details, action_taken, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (telegram_id, incident_type, severity, details, action_taken, now_iso()),
    )
    conn.commit()
    conn.close()
    update_metric("incidents_total", 1)


def get_user_row(user_id: int):
    conn = db()
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM users WHERE telegram_id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def set_user_block(user_id: int, minutes: int):
    until = datetime.utcnow() + timedelta(minutes=minutes)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET blocked_until = ? WHERE telegram_id = ?",
        (until.isoformat(timespec="seconds"), user_id),
    )
    conn.commit()
    conn.close()
    update_metric("blocked_total", 1)


def increment_suspicious(user_id: int, points: int = 1):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE users
        SET suspicious_count = COALESCE(suspicious_count, 0) + ?,
            risk_score = COALESCE(risk_score, 0) + ?
        WHERE telegram_id = ?
        """,
        (points, points * 10, user_id),
    )
    conn.commit()
    conn.close()


def set_admin_authenticated(user_id: int, value: bool, minutes: int = 15):
    session_until = None
    if value:
        session_until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat(timespec="seconds")
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET auth_admin = ?, admin_session_until = ? WHERE telegram_id = ?",
        (1 if value else 0, session_until, user_id),
    )
    conn.commit()
    conn.close()


def is_admin(config: dict, user_id: int) -> bool:
    return config["ADMIN_ID"] is not None and user_id == config["ADMIN_ID"]


def has_admin_session(user_id: int) -> bool:
    row = get_user_row(user_id)
    if not row:
        return False
    if int(row["auth_admin"] or 0) != 1:
        return False
    until = parse_iso(row["admin_session_until"])
    if not until:
        return False
    return datetime.utcnow() < until


def user_is_blocked(user_id: int):
    row = get_user_row(user_id)
    if not row:
        return False, None
    blocked_until = parse_iso(row["blocked_until"])
    if blocked_until and datetime.utcnow() < blocked_until:
        return True, blocked_until
    return False, None


ANTI_SPAM = {}
VERIFY_ATTEMPTS = {}
SECURITY_PATTERNS = [
    (re.compile(r"(?i)\b(select|union|drop|insert|delete|update|alter|exec)\b"), "SQL-подобные ключевые слова"),
    (re.compile(r"(?i)<script|javascript:|onerror=|onload="), "XSS-подобные конструкции"),
    (re.compile(r"([\"'`;]{3,}|--|/\*)", re.I), "подозрительные управляющие символы"),
    (re.compile(r"(?i)\b(token|api[_-]?key|secret|passwd|password)\b"), "чувствительные идентификаторы"),
]


def anti_spam_check(user_id: int):
    current = time.time()
    window = ANTI_SPAM.setdefault(user_id, [])
    window[:] = [t for t in window if current - t <= 10]
    window.append(current)

    if len(window) > 7:
        return False, "Слишком много сообщений за короткое время."
    return True, None


def analyze_text_for_threats(text: str):
    findings = []
    if len(text) > 500:
        findings.append("слишком длинный ввод")
    for pattern, description in SECURITY_PATTERNS:
        if pattern.search(text):
            findings.append(description)
    if text.count("/") > 5:
        findings.append("избыточное количество служебных символов")
    return findings


def compute_risk_label(score: int):
    if score >= 80:
        return "критический"
    if score >= 50:
        return "высокий"
    if score >= 25:
        return "повышенный"
    return "нормальный"


def get_ids_stats():
    conn = db()
    cur = conn.cursor()

    total_events = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    suspicious = cur.execute(
        "SELECT COUNT(*) AS c FROM events WHERE severity IN ('medium','high','critical')"
    ).fetchone()["c"]
    critical = cur.execute(
        "SELECT COUNT(*) AS c FROM events WHERE severity = 'critical'"
    ).fetchone()["c"]
    incidents = cur.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()["c"]

    conn.close()
    return {
        "total_events": total_events,
        "suspicious": suspicious,
        "critical": critical,
        "incidents": incidents,
    }


async def notify_admin(context: ContextTypes.DEFAULT_TYPE, config: dict, text: str):
    admin_id = config.get("ADMIN_ID")
    if not admin_id:
        return
    try:
        await context.bot.send_message(chat_id=admin_id, text=text)
    except Exception as e:
        logger.warning("Не удалось уведомить администратора: %s", e)


def make_profile_text(row):
    if not row:
        return "Профиль не найден."
    risk_label = compute_risk_label(int(row["risk_score"] or 0))
    blocked_until = row["blocked_until"] or "нет"
    return (
        f"👤 Профиль пользователя\n\n"
        f"ID: {row['telegram_id']}\n"
        f"Username: @{row['username'] or '-'}\n"
        f"Имя: {row['first_name'] or '-'}\n"
        f"Регистрация: {row['registered_at'] or '-'}\n"
        f"Последняя активность: {row['last_seen'] or '-'}\n"
        f"Подозрительных действий: {row['suspicious_count'] or 0}\n"
        f"Risk score: {row['risk_score'] or 0}\n"
        f"Уровень риска: {risk_label}\n"
        f"Блокировка до: {blocked_until}\n"
    )


async def ensure_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    register_user(update)
    user = update.effective_user
    if user:
        update_metric("messages_total", 1)
        log_event(user.id, "message", "low", "Получено сообщение/команда")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    text = (
        f"Добро пожаловать в {APP_NAME}.\n\n"
        "Это учебный Telegram-бот для демонстрации защиты информации:\n"
        "• анализ угроз\n"
        "• контроль доступа\n"
        "• IDS и SOC-мониторинг\n"
        "• журналирование событий\n"
        "• симуляции атак и отчёты\n\n"
        f"{HINT_TEXT}"
    )
    await update.message.reply_text(text, reply_markup=MAIN_KEYBOARD)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(MENU_COMMANDS_TEXT, reply_markup=MAIN_KEYBOARD)


async def menu_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text("Открыто меню команд.", reply_markup=MAIN_KEYBOARD)


async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(
        "SafeGate Research Bot — прототип защищённого Telegram-бота для анализа угроз, "
        "демонстрации защитных механизмов, регистрации инцидентов и формирования отчётности."
    )


async def threats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(THREATS_TEXT)


async def architecture(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(ARCHITECTURE_TEXT)


async def policy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(POLICY_TEXT)


async def profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    row = get_user_row(update.effective_user.id)
    await update.message.reply_text(make_profile_text(row))


async def check_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id

    blocked, until = user_is_blocked(user_id)
    if blocked:
        await update.message.reply_text(f"Вы временно заблокированы до {until}.")
        return

    ok, reason = anti_spam_check(user_id)
    if not ok:
        increment_suspicious(user_id, 1)
        log_event(user_id, "spam", "medium", reason)
        await update.message.reply_text(f"⛔ {reason}")
        return

    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Использование: /check текст_для_анализа")
        return

    update_metric("checks_total", 1)

    findings = analyze_text_for_threats(text)
    if findings:
        increment_suspicious(user_id, max(1, len(findings)))
        log_event(user_id, "check", "high", f"Подозрительный ввод: {', '.join(findings)}")
        create_incident(
            user_id,
            "suspicious_input",
            "high",
            f"Обнаружены признаки: {', '.join(findings)}",
            "Ввод помечен как подозрительный",
        )

        row = get_user_row(user_id)
        if row and int(row["suspicious_count"] or 0) >= 5:
            set_user_block(user_id, 10)
            await update.message.reply_text(
                "⚠️ Обнаружен подозрительный ввод.\n"
                f"Признаки: {', '.join(findings)}\n\n"
                "Пользователь временно заблокирован на 10 минут."
            )
        else:
            await update.message.reply_text(
                "⚠️ Обнаружен подозрительный ввод.\n"
                f"Признаки: {', '.join(findings)}"
            )

        config = context.bot_data["config"]
        await notify_admin(
            context,
            config,
            f"🚨 Инцидент: подозрительный ввод\nUser ID: {user_id}\nПризнаки: {', '.join(findings)}",
        )
    else:
        log_event(user_id, "check", "low", "Ввод признан безопасным")
        await update.message.reply_text(
            "✅ Ввод не содержит явных признаков инъекций или опасных конструкций."
        )


async def verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id
    config = context.bot_data["config"]

    blocked, until = user_is_blocked(user_id)
    if blocked:
        await update.message.reply_text(f"Вы временно заблокированы до {until}.")
        return

    code = " ".join(context.args).strip()
    if not code:
        await update.message.reply_text("Использование: /verify ваш_код")
        return

    state = VERIFY_ATTEMPTS.setdefault(user_id, {"count": 0, "last": 0})
    if time.time() - state["last"] > 300:
        state["count"] = 0

    submitted_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

    if hmac.compare_digest(submitted_hash, config["SECRET_CODE_HASH"]):
        state["count"] = 0
        state["last"] = time.time()
        log_event(user_id, "verify", "low", "Успешная проверка секрета")
        await update.message.reply_text("✅ Секретный код подтверждён.")
        return

    state["count"] += 1
    state["last"] = time.time()
    increment_suspicious(user_id, 1)
    update_metric("auth_fail_total", 1)
    log_event(user_id, "verify", "medium", f"Неуспешная проверка секрета. Попытка {state['count']}")

    if state["count"] >= 5:
        set_user_block(user_id, 15)
        create_incident(
            user_id,
            "bruteforce_verify",
            "critical",
            "Многократные неуспешные попытки проверки секрета",
            "Временная блокировка на 15 минут",
        )
        config = context.bot_data["config"]
        await notify_admin(
            context,
            config,
            f"🚨 Critical: возможный brute force /verify\nUser ID: {user_id}\nПопыток: {state['count']}",
        )
        await update.message.reply_text("⛔ Слишком много неверных попыток. Блокировка на 15 минут.")
        return

    await update.message.reply_text(f"❌ Неверный код. Попытка {state['count']} из 5.")


async def risk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    row = get_user_row(update.effective_user.id)
    score = int(row["risk_score"] or 0)
    suspicious = int(row["suspicious_count"] or 0)
    label = compute_risk_label(score)

    reasons = []
    if suspicious:
        reasons.append(f"подозрительных действий: {suspicious}")
    if parse_iso(row["blocked_until"]):
        reasons.append("ранее применялась блокировка")
    if not reasons:
        reasons.append("аномальная активность не выявлена")

    await update.message.reply_text(
        "📉 Риск-профиль пользователя\n\n"
        f"Risk score: {score}\n"
        f"Уровень риска: {label}\n"
        "Причины:\n- " + "\n- ".join(reasons)
    )


async def ids(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    stats = get_ids_stats()
    await update.message.reply_text(
        "🛡 IDS статус\n\n"
        f"Всего событий: {stats['total_events']}\n"
        f"Подозрительных событий: {stats['suspicious']}\n"
        f"Критических событий: {stats['critical']}\n"
        f"Инцидентов: {stats['incidents']}\n"
        "Статус: активна"
    )


async def soc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    conn = db()
    cur = conn.cursor()
    users_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    active_blocks = cur.execute(
        "SELECT COUNT(*) AS c FROM users WHERE blocked_until IS NOT NULL"
    ).fetchone()["c"]
    latest_inc = cur.execute(
        "SELECT incident_type, severity, created_at FROM incidents ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    latest_line = "нет"
    if latest_inc:
        latest_line = f"{latest_inc['incident_type']} / {latest_inc['severity']} / {latest_inc['created_at']}"

    total_incidents = get_metric("incidents_total")

    threat_level = "низкий"
    if total_incidents >= 10:
        threat_level = "высокий"
    elif total_incidents >= 5:
        threat_level = "повышенный"

    text = (
        "🏢 SOC / Центр мониторинга\n\n"
        f"Пользователей: {users_count}\n"
        f"Инцидентов: {total_incidents}\n"
        f"Активных блокировок: {active_blocks}\n"
        f"Последний инцидент: {latest_line}\n"
        f"Текущий уровень угрозы: {threat_level}\n"
    )
    await update.message.reply_text(text)


def simulate_attack_payload(kind: str):
    kind = kind.lower()
    mapping = {
        "sql": (
            "SQL Injection",
            "high",
            "Введена строка, похожая на SQL-инъекцию: ' OR 1=1 --",
            "Запрос отклонён, событие записано в журнал, доступ не предоставлен.",
        ),
        "xss": (
            "XSS Injection",
            "high",
            "Обнаружена конструкция <script>alert(1)</script>",
            "Поле очищено, выполнение запрещено, событие зафиксировано.",
        ),
        "spam": (
            "Flood / Spam",
            "medium",
            "Обнаружено превышение лимита сообщений",
            "Применено ограничение частоты запросов.",
        ),
        "bruteforce": (
            "Brute Force",
            "critical",
            "Многократные неуспешные попытки проверки кода",
            "Пользователь временно заблокирован.",
        ),
        "admin": (
            "Privilege Escalation",
            "high",
            "Попытка доступа к административной функции без прав",
            "Доступ запрещён, инцидент зарегистрирован.",
        ),
        "leak": (
            "Token Leakage",
            "critical",
            "Симуляция компрометации токена бота",
            "Рекомендуется немедленная ротация токена и проверка конфигурации.",
        ),
    }
    return mapping.get(kind)


async def simulate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Использование: /simulate sql|xss|spam|bruteforce|admin|leak")
        return

    kind = context.args[0].lower()
    payload = simulate_attack_payload(kind)
    if not payload:
        await update.message.reply_text("Неизвестный тип. Доступно: sql, xss, spam, bruteforce, admin, leak")
        return

    title, severity, details, reaction = payload
    update_metric("simulations_total", 1)
    increment_suspicious(user_id, 1 if severity != "critical" else 2)
    log_event(user_id, "simulation", severity, f"{title}: {details}")
    create_incident(user_id, f"simulation_{kind}", severity, details, reaction)

    if kind == "bruteforce":
        set_user_block(user_id, 5)

    text = (
        f"🎯 Симуляция атаки: {title}\n\n"
        f"Описание: {details}\n"
        f"Критичность: {severity}\n"
        f"Реакция системы: {reaction}"
    )
    await update.message.reply_text(text)

    config = context.bot_data["config"]
    await notify_admin(
        context,
        config,
        f"🧪 Симуляция атаки\nUser ID: {user_id}\nТип: {title}\nКритичность: {severity}",
    )


async def demo_attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id

    steps = [
        "Шаг 1/5: Обнаружена разведка и попытка анализа поверхности атаки...",
        "Шаг 2/5: Зафиксирована попытка обхода валидации и внедрения вредоносного ввода...",
        "Шаг 3/5: IDS классифицирует событие как потенциальную атаку...",
        "Шаг 4/5: Система инициирует защитную реакцию и журналирует инцидент...",
        "Шаг 5/5: Администратор уведомлён, риск-профиль пользователя обновлён...",
    ]

    for step in steps:
        await update.message.reply_text(step)

    increment_suspicious(user_id, 2)
    create_incident(
        user_id,
        "demo_attack_chain",
        "high",
        "Демонстрационная цепочка атаки",
        "Проведено логирование, обновлён риск и отправлено уведомление администратору",
    )
    log_event(user_id, "demo_attack", "high", "Запущена демонстрационная цепочка атаки")

    config = context.bot_data["config"]
    await notify_admin(
        context,
        config,
        f"🚨 Demo Attack завершён\nUser ID: {user_id}\nТип: демонстрационная цепочка атаки",
    )

    await update.message.reply_text("✅ Демонстрация завершена. Инцидент зафиксирован.")


async def red(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(RED_TEXT)


async def blue(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    await update.message.reply_text(BLUE_TEXT)


async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    config = context.bot_data["config"]
    user_id = update.effective_user.id

    if not is_admin(config, user_id):
        increment_suspicious(user_id, 1)
        log_event(user_id, "admin_access", "high", "Попытка доступа к админ-команде без прав")
        create_incident(
            user_id,
            "unauthorized_admin_access",
            "high",
            "Попытка обращения к административному интерфейсу",
            "Доступ запрещён",
        )
        await update.message.reply_text("⛔ У вас нет прав администратора.")
        return

    await update.message.reply_text(
        "Введите PIN командой:\n/admin_login 123456\n\n"
        "Сессия администратора будет активна 15 минут."
    )


async def admin_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    config = context.bot_data["config"]
    user_id = update.effective_user.id

    if not is_admin(config, user_id):
        await update.message.reply_text("⛔ У вас нет прав администратора.")
        return

    pin = " ".join(context.args).strip()
    if not pin:
        await update.message.reply_text("Использование: /admin_login ваш_PIN")
        return

    submitted_hash = hashlib.sha256(pin.encode("utf-8")).hexdigest()
    if hmac.compare_digest(submitted_hash, config["ADMIN_PIN_HASH"]):
        set_admin_authenticated(user_id, True, minutes=15)
        log_event(user_id, "admin_login", "low", "Успешный вход администратора")
        await update.message.reply_text("✅ Административная сессия активирована на 15 минут.")
        return

    update_metric("auth_fail_total", 1)
    increment_suspicious(user_id, 1)
    log_event(user_id, "admin_login", "high", "Неуспешный вход администратора")
    create_incident(
        user_id,
        "admin_login_failed",
        "high",
        "Неверный PIN администратора",
        "Доступ не предоставлен",
    )
    await update.message.reply_text("❌ Неверный PIN.")


def require_admin_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    config = context.bot_data["config"]
    user_id = update.effective_user.id
    if not is_admin(config, user_id):
        return False, "⛔ У вас нет прав администратора."
    if not has_admin_session(user_id):
        return False, "⛔ Админ-сессия не активна. Используйте /admin и /admin_login."
    return True, None


async def dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    conn = db()
    cur = conn.cursor()
    users_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    events_count = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    incidents_count = cur.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()["c"]
    suspicious_users = cur.execute(
        "SELECT COUNT(*) AS c FROM users WHERE suspicious_count > 0"
    ).fetchone()["c"]
    blocks_count = cur.execute(
        "SELECT COUNT(*) AS c FROM users WHERE blocked_until IS NOT NULL"
    ).fetchone()["c"]
    conn.close()

    text = (
        "📊 Панель безопасности\n\n"
        f"Пользователей: {users_count}\n"
        f"Событий: {events_count}\n"
        f"Инцидентов: {incidents_count}\n"
        f"Подозрительных пользователей: {suspicious_users}\n"
        f"Блокировок: {blocks_count}\n"
        f"Honeypot срабатываний: {get_metric('honeypot_total')}\n"
        f"Проверок ввода: {get_metric('checks_total')}\n"
        f"Симуляций: {get_metric('simulations_total')}\n"
        f"Ошибок аутентификации: {get_metric('auth_fail_total')}\n"
    )
    await update.message.reply_text(text)


async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    conn = db()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 15"
    ).fetchall()
    conn.close()

    if not rows:
        await update.message.reply_text("Журнал пуст.")
        return

    lines = []
    for r in rows:
        lines.append(
            f"#{r['id']} | {r['created_at']} | {r['severity']} | "
            f"{r['event_type']} | user={r['telegram_id']} | {r['description']}"
        )

    await update.message.reply_text("📜 Последние события:\n\n" + "\n".join(lines))


async def incident(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    arg = context.args[0] if context.args else "latest"

    conn = db()
    cur = conn.cursor()

    if arg == "latest":
        row = cur.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
    else:
        if not arg.isdigit():
            conn.close()
            await update.message.reply_text("Использование: /incident latest или /incident id")
            return
        row = cur.execute("SELECT * FROM incidents WHERE id = ?", (int(arg),)).fetchone()

    conn.close()

    if not row:
        await update.message.reply_text("Инцидент не найден.")
        return

    text = (
        f"🧾 Инцидент #{row['id']}\n\n"
        f"Тип: {row['incident_type']}\n"
        f"Severity: {row['severity']}\n"
        f"User ID: {row['telegram_id']}\n"
        f"Детали: {row['details']}\n"
        f"Принятые меры: {row['action_taken']}\n"
        f"Дата: {row['created_at']}"
    )
    await update.message.reply_text(text)


async def case(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    conn = db()
    cur = conn.cursor()

    if not context.args or context.args[0] == "latest":
        inc = cur.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        if not inc:
            conn.close()
            await update.message.reply_text("Инцидентов пока нет.")
            return
        target_user = inc["telegram_id"]
    elif context.args[0] == "user" and len(context.args) > 1 and context.args[1].isdigit():
        target_user = int(context.args[1])
        inc = cur.execute(
            "SELECT * FROM incidents WHERE telegram_id = ? ORDER BY id DESC LIMIT 1",
            (target_user,),
        ).fetchone()
        if not inc:
            conn.close()
            await update.message.reply_text("Для указанного пользователя инцидентов не найдено.")
            return
    else:
        conn.close()
        await update.message.reply_text("Использование: /case latest или /case user <id>")
        return

    recent_events = cur.execute(
        "SELECT * FROM events WHERE telegram_id = ? ORDER BY id DESC LIMIT 10",
        (target_user,),
    ).fetchall()
    conn.close()

    events_block = "\n".join(
        [
            f"- {e['created_at']} | {e['severity']} | {e['event_type']} | {e['description']}"
            for e in recent_events
        ]
    ) or "- Нет событий"

    text = (
        "🕵️ Форензика / Case Report\n\n"
        f"User ID: {target_user}\n"
        f"Последний инцидент: {inc['incident_type']}\n"
        f"Severity: {inc['severity']}\n"
        f"Детали: {inc['details']}\n"
        f"Принятые меры: {inc['action_taken']}\n"
        f"Дата: {inc['created_at']}\n\n"
        f"Последние события:\n{events_block}"
    )
    await update.message.reply_text(text)


def build_text_report():
    conn = db()
    cur = conn.cursor()

    users_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    incidents_count = cur.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()["c"]
    events_count = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    top_incidents = cur.execute("""
        SELECT incident_type, COUNT(*) AS c
        FROM incidents
        GROUP BY incident_type
        ORDER BY c DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    lines = [
        "ОТЧЁТ ПО БЕЗОПАСНОСТИ",
        "",
        f"Дата формирования: {now_iso()}",
        f"Пользователей: {users_count}",
        f"Событий: {events_count}",
        f"Инцидентов: {incidents_count}",
        "",
        "Наиболее частые инциденты:",
    ]
    for row in top_incidents:
        lines.append(f"- {row['incident_type']}: {row['c']}")
    if not top_incidents:
        lines.append("- нет данных")

    lines.extend([
        "",
        "Рекомендации:",
        "- Выполнять ротацию токена при подозрении на компрометацию",
        "- Ограничивать доступ к административным функциям",
        "- Усилить контроль вредоносного ввода",
        "- Подключить внешнее хранилище логов при промышленной эксплуатации",
    ])
    return "\n".join(lines)


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return
    await update.message.reply_text(build_text_report())


def build_html_report():
    conn = db()
    cur = conn.cursor()

    users_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    incidents_count = cur.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()["c"]
    events_count = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    top_incidents = cur.execute("""
        SELECT incident_type, COUNT(*) AS c
        FROM incidents
        GROUP BY incident_type
        ORDER BY c DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    items = "".join(
        f"<li>{html.escape(row['incident_type'])}: {row['c']}</li>"
        for row in top_incidents
    ) or "<li>нет данных</li>"

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.5; }}
h1 {{ margin-bottom: 8px; }}
.card {{ border: 1px solid #ccc; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
</style>
</head>
<body>
<h1>Отчёт по безопасности</h1>
<p>Дата формирования: {html.escape(now_iso())}</p>
<div class="card">
<p><b>Пользователей:</b> {users_count}</p>
<p><b>Событий:</b> {events_count}</p>
<p><b>Инцидентов:</b> {incidents_count}</p>
</div>
<div class="card">
<h2>Частые инциденты</h2>
<ul>{items}</ul>
</div>
<div class="card">
<h2>Рекомендации</h2>
<ul>
<li>Выполнять ротацию токена при подозрении на компрометацию.</li>
<li>Ограничивать административный доступ по Telegram ID и PIN.</li>
<li>Применять валидацию входных данных и лимиты частоты запросов.</li>
<li>Использовать внешнее защищённое хранилище для журналов в production.</li>
</ul>
</div>
</body>
</html>"""


async def report_html(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    content = build_html_report()
    filename = REPORTS_DIR / f"security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    filename.write_text(content, encoding="utf-8")

    with open(filename, "rb") as f:
        await update.message.reply_document(document=InputFile(f, filename=filename.name))


async def chart_attacks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    allowed, message = require_admin_session(update, context)
    if not allowed:
        await update.message.reply_text(message)
        return

    conn = db()
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT incident_type, COUNT(*) AS c
        FROM incidents
        GROUP BY incident_type
        ORDER BY c DESC
        LIMIT 8
    """).fetchall()
    conn.close()

    if not rows:
        await update.message.reply_text("Недостаточно данных для построения графика.")
        return

    labels = [r["incident_type"] for r in rows]
    values = [r["c"] for r in rows]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values)
    plt.xticks(rotation=35, ha="right")
    plt.ylabel("Количество")
    plt.title("Инциденты по типам")
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)

    await update.message.reply_photo(photo=buf, caption="График инцидентов безопасности")


HONEYPOT_NAMES = {"root", "token", "database", "admin_full"}


async def honeypot_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id
    command_text = update.message.text.strip().split()[0].lstrip("/")

    if command_text not in HONEYPOT_NAMES:
        return

    update_metric("honeypot_total", 1)
    increment_suspicious(user_id, 2)
    log_event(user_id, "honeypot", "critical", f"Сработала honeypot-команда /{command_text}")
    create_incident(
        user_id,
        "honeypot_trigger",
        "critical",
        f"Попытка использования ложной административной команды /{command_text}",
        "Событие маркировано как разведка / попытка несанкционированного доступа",
    )

    config = context.bot_data["config"]
    await notify_admin(
        context,
        config,
        f"🚨 Honeypot trigger\nUser ID: {user_id}\nКоманда: /{command_text}",
    )

    await update.message.reply_text(
        "⛔ Запрос отклонён. Событие зарегистрировано как подозрительное."
    )


async def text_menu_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update, context)
    user_id = update.effective_user.id

    ok, reason = anti_spam_check(user_id)
    if not ok:
        increment_suspicious(user_id, 1)
        await update.message.reply_text(f"⛔ {reason}")
        return

    text = update.message.text.strip()

    if text == "ℹ️ Информация":
        await info(update, context)
    elif text == "🧱 Архитектура":
        await architecture(update, context)
    elif text == "⚠️ Угрозы":
        await threats(update, context)
    elif text == "📜 Политика ИБ":
        await policy(update, context)
    elif text == "📉 Риск":
        await risk(update, context)
    elif text == "🛡 IDS":
        await ids(update, context)
    elif text == "🏢 SOC":
        await soc(update, context)
    elif text == "🎭 Demo Attack":
        await demo_attack(update, context)
    elif text == "🔴 Red Team":
        await red(update, context)
    elif text == "🔵 Blue Team":
        await blue(update, context)
    elif text == "👤 Профиль":
        await profile(update, context)
    elif text == "📋 Меню команд":
        await help_command(update, context)
    elif text == "🔍 Проверить ввод":
        await update.message.reply_text("Используй команду:\n/check текст")
    elif text == "🔐 Проверить секрет":
        await update.message.reply_text("Используй команду:\n/verify код")
    else:
        await update.message.reply_text(
            "Сообщение получено.\n"
            "Для работы используй кнопки меню или команды.\n\n"
            + HINT_TEXT
        )


async def set_commands(application: Application):
    commands = [
        BotCommand("start", "Запуск бота"),
        BotCommand("help", "Справка"),
        BotCommand("menu", "Показать меню"),
        BotCommand("info", "Информация о боте"),
        BotCommand("architecture", "Архитектура защищённого бота"),
        BotCommand("threats", "Основные угрозы"),
        BotCommand("policy", "Политика безопасной эксплуатации"),
        BotCommand("profile", "Профиль пользователя"),
        BotCommand("check", "Анализ подозрительного ввода"),
        BotCommand("verify", "Проверка секретного кода"),
        BotCommand("risk", "Риск-профиль пользователя"),
        BotCommand("ids", "Статус IDS"),
        BotCommand("soc", "Центр мониторинга"),
        BotCommand("simulate", "Симуляция атаки"),
        BotCommand("demo_attack", "Демонстрация цепочки атаки"),
        BotCommand("red", "Red Team режим"),
        BotCommand("blue", "Blue Team режим"),
        BotCommand("admin", "Запрос входа администратора"),
        BotCommand("admin_login", "Вход по PIN"),
        BotCommand("dashboard", "Панель безопасности"),
        BotCommand("logs", "Журнал событий"),
        BotCommand("incident", "Карточка инцидента"),
        BotCommand("case", "Форензика по инциденту"),
        BotCommand("report", "Текстовый отчёт"),
        BotCommand("report_html", "HTML-отчёт файлом"),
        BotCommand("chart_attacks", "График инцидентов"),
    ]
    await application.bot.set_my_commands(commands)


async def post_init(application: Application):
    await set_commands(application)


def build_application(config: dict):
    application = Application.builder().token(config["BOT_TOKEN"]).post_init(post_init).build()
    application.bot_data["config"] = config

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("menu", menu_command))
    application.add_handler(CommandHandler("info", info))
    application.add_handler(CommandHandler("architecture", architecture))
    application.add_handler(CommandHandler("threats", threats))
    application.add_handler(CommandHandler("policy", policy))
    application.add_handler(CommandHandler("profile", profile))
    application.add_handler(CommandHandler("check", check_input))
    application.add_handler(CommandHandler("verify", verify))
    application.add_handler(CommandHandler("risk", risk))
    application.add_handler(CommandHandler("ids", ids))
    application.add_handler(CommandHandler("soc", soc))
    application.add_handler(CommandHandler("simulate", simulate))
    application.add_handler(CommandHandler("demo_attack", demo_attack))
    application.add_handler(CommandHandler("red", red))
    application.add_handler(CommandHandler("blue", blue))
    application.add_handler(CommandHandler("admin", admin))
    application.add_handler(CommandHandler("admin_login", admin_login))
    application.add_handler(CommandHandler("dashboard", dashboard))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("incident", incident))
    application.add_handler(CommandHandler("case", case))
    application.add_handler(CommandHandler("report", report))
    application.add_handler(CommandHandler("report_html", report_html))
    application.add_handler(CommandHandler("chart_attacks", chart_attacks))

    for hp in HONEYPOT_NAMES:
        application.add_handler(CommandHandler(hp, honeypot_handler))

    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, text_menu_router)
    )

    return application


def main():
    init_db()
    config = load_config()
    application = build_application(config)
    logger.info("Starting %s", APP_NAME)
    application.run_polling()


if __name__ == "__main__":
    main()
