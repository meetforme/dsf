import asyncio
import hashlib
import html
import logging
import os
import random
import re
import sqlite3
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from telegram import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    AIORateLimiter,
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

APP_NAME = "SafeGate Research Bot"
UTC = timezone.utc
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "safegate_research.db"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(APP_NAME)


@dataclass
class Config:
    bot_token: str
    admin_id: Optional[int]
    secret_code: str
    admin_pin: str


def load_config() -> Config:
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)

    raw = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            raw[key.strip()] = value.strip()

    bot_token = os.getenv("BOT_TOKEN", raw.get("BOT_TOKEN", "")).strip()
    admin_id_raw = os.getenv("ADMIN_ID", raw.get("ADMIN_ID", "")).strip()
    secret_code = os.getenv("SECRET_CODE", raw.get("SECRET_CODE", "safegate")).strip()
    admin_pin = os.getenv("ADMIN_PIN", raw.get("ADMIN_PIN", "123456")).strip()

    if not bot_token:
        raise RuntimeError(f"Не найден BOT_TOKEN. Проверен файл: {env_path}")

    admin_id = int(admin_id_raw) if admin_id_raw.isdigit() else None
    return Config(bot_token=bot_token, admin_id=admin_id, secret_code=secret_code, admin_pin=admin_pin)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                telegram_id INTEGER PRIMARY KEY,
                username TEXT,
                full_name TEXT,
                registered_at TEXT NOT NULL,
                suspicious_count INTEGER NOT NULL DEFAULT 0,
                denied_access_count INTEGER NOT NULL DEFAULT 0,
                spam_count INTEGER NOT NULL DEFAULT 0,
                brute_force_count INTEGER NOT NULL DEFAULT 0,
                honeypot_count INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                response TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def ensure_user(user) -> None:
    if user is None:
        return
    username = user.username or ""
    full_name = (user.full_name or "").strip()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT telegram_id FROM users WHERE telegram_id = ?", (user.id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET username=?, full_name=?, last_seen=? WHERE telegram_id=?",
                (username, full_name, now_iso(), user.id),
            )
        else:
            conn.execute(
                "INSERT INTO users (telegram_id, username, full_name, registered_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                (user.id, username, full_name, now_iso(), now_iso()),
            )


def log_event(telegram_id: Optional[int], event_type: str, severity: str, details: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (telegram_id, event_type, severity, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (telegram_id, event_type, severity, details[:4000], now_iso()),
        )


def create_incident(telegram_id: Optional[int], title: str, summary: str, severity: str, response: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO incidents (telegram_id, title, summary, severity, response, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (telegram_id, title, summary[:4000], severity, response[:4000], now_iso()),
        )


def increment_user_field(user_id: int, field: str, amount: int = 1) -> None:
    allowed = {
        "suspicious_count",
        "denied_access_count",
        "spam_count",
        "brute_force_count",
        "honeypot_count",
    }
    if field not in allowed:
        return
    with get_conn() as conn:
        conn.execute(
            f"UPDATE users SET {field} = COALESCE({field}, 0) + ? WHERE telegram_id = ?",
            (amount, user_id),
        )


def get_user_stats(user_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE telegram_id = ?", (user_id,)).fetchone()
        if not row:
            return {
                "suspicious_count": 0,
                "denied_access_count": 0,
                "spam_count": 0,
                "brute_force_count": 0,
                "honeypot_count": 0,
                "registered_at": "—",
            }
        return dict(row)


def count_rows(table: str) -> int:
    with get_conn() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def recent_events(limit: int = 10):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def recent_incidents(limit: int = 5):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def event_type_counts() -> Counter:
    with get_conn() as conn:
        rows = conn.execute("SELECT event_type, COUNT(*) as c FROM events GROUP BY event_type").fetchall()
    return Counter({row["event_type"]: row["c"] for row in rows})


def severity_counts() -> Counter:
    with get_conn() as conn:
        rows = conn.execute("SELECT severity, COUNT(*) as c FROM events GROUP BY severity").fetchall()
    return Counter({row["severity"]: row["c"] for row in rows})


def compute_risk(stats: dict) -> tuple[str, int, list[str]]:
    score = 0
    reasons = []

    suspicious = int(stats.get("suspicious_count", 0) or 0)
    denied = int(stats.get("denied_access_count", 0) or 0)
    spam = int(stats.get("spam_count", 0) or 0)
    brute = int(stats.get("brute_force_count", 0) or 0)
    honeypot = int(stats.get("honeypot_count", 0) or 0)

    if suspicious:
        score += suspicious * 10
        reasons.append(f"подозрительный ввод: {suspicious}")
    if denied:
        score += denied * 8
        reasons.append(f"запрещённые обращения: {denied}")
    if spam:
        score += spam * 12
        reasons.append(f"сработки антиспама: {spam}")
    if brute:
        score += brute * 15
        reasons.append(f"неверные попытки проверки кода: {brute}")
    if honeypot:
        score += honeypot * 20
        reasons.append(f"обращения к honeypot-командам: {honeypot}")

    if score >= 80:
        level = "Критический"
    elif score >= 45:
        level = "Высокий"
    elif score >= 20:
        level = "Повышенный"
    else:
        level = "Низкий"
    return level, score, reasons or ["аномалии не выявлены"]


SUSPICIOUS_PATTERNS = [
    (re.compile(r"(select\s+.+from|union\s+select|drop\s+table|insert\s+into)", re.I), "SQL-подобная конструкция"),
    (re.compile(r"(<script|javascript:|onerror=|onload=)", re.I), "XSS/JS-подобная конструкция"),
    (re.compile(r"(\.\./|/etc/passwd|cmd\.exe|powershell)", re.I), "попытка обращения к системным путям/командам"),
    (re.compile(r"([""'`;]{3,}|--|/\*)", re.I), "подозрительные управляющие символы"),
    (re.compile(r"(token|api[_ -]?key|secret|password)\s*[=:]", re.I), "похоже на передачу секрета в открытом виде"),
]


def analyze_text_security(text: str) -> tuple[str, list[str]]:
    findings = []
    clean = text.strip()
    if not clean:
        return "Низкий", ["ввод пустой"]
    if len(clean) > 350:
        findings.append("слишком длинный ввод")
    if clean.count("\n") > 8:
        findings.append("многострочная полезная нагрузка")
    for pattern, label in SUSPICIOUS_PATTERNS:
        if pattern.search(clean):
            findings.append(label)
    severity = "Низкий"
    if any("SQL" in f or "XSS" in f for f in findings):
        severity = "Высокий"
    elif findings:
        severity = "Средний"
    return severity, findings or ["критичных шаблонов не обнаружено"]


def menu_markup() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton("🛡 Статус защиты", callback_data="menu_dashboard"), InlineKeyboardButton("📚 Угрозы", callback_data="menu_threats")],
        [InlineKeyboardButton("🏗 Архитектура", callback_data="menu_architecture"), InlineKeyboardButton("🧪 Проверка ввода", callback_data="menu_check")],
        [InlineKeyboardButton("🎭 Симуляции атак", callback_data="menu_simulate"), InlineKeyboardButton("📈 IDS", callback_data="menu_ids")],
        [InlineKeyboardButton("🧭 Модель угроз", callback_data="menu_model"), InlineKeyboardButton("📄 Отчёт", callback_data="menu_report")],
    ]
    return InlineKeyboardMarkup(keyboard)


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    cfg: Config = context.application.bot_data["config"]
    user = update.effective_user
    return bool(cfg.admin_id and user and user.id == cfg.admin_id)


async def maybe_alert_admin(context: ContextTypes.DEFAULT_TYPE, message: str) -> None:
    cfg: Config = context.application.bot_data["config"]
    if not cfg.admin_id:
        return
    try:
        await context.bot.send_message(cfg.admin_id, message)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Не удалось отправить уведомление админу: %s", exc)


async def anti_spam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user:
        return False
    now = datetime.now(UTC)
    bucket = context.application.user_data.setdefault(user.id, {})
    msg_times = bucket.setdefault("msg_times", [])
    msg_times[:] = [t for t in msg_times if now - t < timedelta(seconds=12)]
    msg_times.append(now)
    blocked_until = bucket.get("blocked_until")

    if blocked_until and now < blocked_until:
        await update.effective_message.reply_text(
            f"⛔ Временная блокировка активна до {blocked_until.astimezone().strftime('%H:%M:%S')} из-за подозрительной активности."
        )
        return True

    if len(msg_times) >= 6:
        bucket["blocked_until"] = now + timedelta(minutes=3)
        increment_user_field(user.id, "spam_count")
        log_event(user.id, "spam_detected", "high", f"Частота сообщений: {len(msg_times)} за 12 секунд")
        create_incident(
            user.id,
            "Антиспам-блокировка",
            "Зафиксирована аномально высокая частота сообщений.",
            "high",
            "Пользователь временно заблокирован на 3 минуты.",
        )
        await maybe_alert_admin(context, f"🚨 Антиспам: пользователь {user.id} временно заблокирован.")
        await update.effective_message.reply_text("🚨 Обнаружен флуд. Доступ временно ограничен на 3 минуты.")
        return True
    return False


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    log_event(update.effective_user.id if update.effective_user else None, "start", "info", "Запуск бота")
    text = (
        f"<b>{APP_NAME}</b>\n\n"
        "Прототип защищённого Telegram-бота для исследовательской работы по ИБ.\n"
        "Бот демонстрирует угрозы, модель защиты, IDS-мониторинг, отчёты и обработку инцидентов."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=menu_markup())


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Ключевые команды</b>\n"
        "/menu — кнопочное меню\n"
        "/info — назначение бота\n"
        "/architecture — архитектура защищённого бота\n"
        "/threats — актуальные угрозы\n"
        "/threat_model — модель угроз\n"
        "/security — меры защиты\n"
        "/check &lt;текст&gt; — анализ пользовательского ввода\n"
        "/verify &lt;код&gt; — безопасная проверка секрета\n"
        "/risk — оценка риска пользователя\n"
        "/ids — статус IDS\n"
        "/simulate sql|xss|spam|bruteforce|admin|leak — демонстрация атак\n"
        "/demo_attack — сценарий атаки в реальном времени\n"
        "/red и /blue — взгляд атакующего и защитника\n"
        "/soc — центр мониторинга\n"
        "/dashboard — админ-панель\n"
        "/logs — последние события\n"
        "/incident latest — карточка инцидента\n"
        "/report — текстовый отчёт\n"
        "/report_html — HTML-отчёт\n"
        "/chart_attacks — график атак\n"
        "/admin → /admin_login &lt;PIN&gt; — двухшаговый вход администратора"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text("Выбери раздел:", reply_markup=menu_markup())


async def info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>О проекте</b>\n"
        "Бот разработан как демонстрационная платформа для анализа защиты информации в Telegram-ботах.\n\n"
        "Он показывает, как реализуются:\n"
        "• валидация ввода;\n"
        "• разграничение доступа;\n"
        "• журналирование;\n"
        "• обнаружение атак;\n"
        "• обработка инцидентов;\n"
        "• аналитическая отчётность."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def architecture(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Архитектура защищённого Telegram-бота</b>\n"
        "1. Интерфейс Telegram Bot API.\n"
        "2. Слой обработки команд и сообщений.\n"
        "3. Модуль валидации ввода и антиспам-контроль.\n"
        "4. Подсистема IDS/логирования.\n"
        "5. Модуль реагирования на инциденты.\n"
        "6. Хранилище SQLite для событий и профилей риска.\n"
        "7. Отчётный модуль (текст, HTML, графики)."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def threats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Ключевые угрозы для Telegram-ботов</b>\n"
        "• компрометация токена бота;\n"
        "• несанкционированный доступ к административным командам;\n"
        "• флуд и abuse-активность;\n"
        "• вредоносный пользовательский ввод;\n"
        "• утечка конфигурации и секретов;\n"
        "• хранение чувствительных данных в открытом виде;\n"
        "• отсутствие журналирования и форензики."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def threat_model(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Модель угроз</b>\n"
        "Активы: токен, журнал событий, профиль пользователя, административные функции, отчёты.\n\n"
        "Нарушители: внешний пользователь, спамер, инсайдер, оператор с избыточными правами.\n\n"
        "Векторы атак:\n"
        "• brute force;\n"
        "• SQL/XSS-подобный ввод;\n"
        "• эскалация привилегий;\n"
        "• злоупотребление служебными командами;\n"
        "• утечка токена и секретов."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def security(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Меры защиты</b>\n"
        "• токен и PIN вынесены в .env;\n"
        "• админ-функции защищены проверкой Telegram ID и PIN;\n"
        "• подозрительный ввод анализируется шаблонами;\n"
        "• включены антиспам и блокировка;\n"
        "• события и инциденты журналируются;\n"
        "• отчёты позволяют анализировать динамику атак;\n"
        "• honeypot-команды выявляют разведку злоумышленника."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def policies(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Политика безопасной эксплуатации</b>\n"
        "1. Не публиковать BOT_TOKEN.\n"
        "2. Ограничивать доступ к серверу и .env.\n"
        "3. Регулярно ротировать секреты.\n"
        "4. Анализировать журналы событий.\n"
        "5. Изолировать хранилище отчётов и базы.\n"
        "6. Применять принцип минимальных привилегий."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def check_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await anti_spam(update, context):
        return
    ensure_user(update.effective_user)
    text = " ".join(context.args).strip()
    if not text:
        await update.effective_message.reply_text("Использование: /check <текст для анализа>")
        return

    severity, findings = analyze_text_security(text)
    if severity in {"Средний", "Высокий"}:
        increment_user_field(update.effective_user.id, "suspicious_count")
        sev = "medium" if severity == "Средний" else "high"
        log_event(update.effective_user.id, "input_analysis", sev, "; ".join(findings))
        if severity == "Высокий":
            create_incident(
                update.effective_user.id,
                "Обнаружен опасный ввод",
                f"Текст пользователя содержит признаки угрозы: {', '.join(findings)}",
                "high",
                "Ввод отклонён, пользователю выдано предупреждение, событие занесено в журнал.",
            )
            await maybe_alert_admin(context, f"🚨 Высокорисковый ввод от пользователя {update.effective_user.id}: {', '.join(findings)}")

    text_out = (
        f"<b>Результат анализа</b>\n"
        f"Уровень: <b>{severity}</b>\n"
        f"Наблюдения:\n- " + "\n- ".join(html.escape(x) for x in findings)
    )
    await update.effective_message.reply_text(text_out, parse_mode=ParseMode.HTML)


async def verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await anti_spam(update, context):
        return
    ensure_user(update.effective_user)
    candidate = " ".join(context.args).strip()
    if not candidate:
        await update.effective_message.reply_text("Использование: /verify <секретный_код>")
        return
    cfg: Config = context.application.bot_data["config"]
    ok = hashlib.sha256(candidate.encode()).hexdigest() == hashlib.sha256(cfg.secret_code.encode()).hexdigest()
    if ok:
        log_event(update.effective_user.id, "verify_success", "info", "Успешная проверка секрета")
        await update.effective_message.reply_text("✅ Код подтверждён. Проверка выполнена безопасным сравнением по SHA-256.")
    else:
        increment_user_field(update.effective_user.id, "brute_force_count")
        log_event(update.effective_user.id, "verify_fail", "medium", "Неверная попытка проверки секрета")
        create_incident(
            update.effective_user.id,
            "Неверная попытка верификации",
            "Зафиксирована неудачная попытка проверки секретного кода.",
            "medium",
            "Попытка записана для последующего анализа вероятного brute force.",
        )
        await update.effective_message.reply_text("❌ Код неверный. Событие журналировано как возможный признак brute force.")


async def risk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    stats = get_user_stats(update.effective_user.id)
    level, score, reasons = compute_risk(stats)
    text = (
        f"<b>Оценка риска пользователя</b>\n"
        f"Уровень: <b>{level}</b>\n"
        f"Скоринг: <b>{score}</b>\n"
        f"Причины:\n- " + "\n- ".join(html.escape(r) for r in reasons)
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def ids(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    events = count_rows("events")
    incidents = count_rows("incidents")
    sev = severity_counts()
    text = (
        "<b>IDS / Мониторинг безопасности</b>\n"
        f"Всего событий: <b>{events}</b>\n"
        f"Инцидентов: <b>{incidents}</b>\n"
        f"Критичных/high: <b>{sev.get('high', 0)}</b>\n"
        f"Средних: <b>{sev.get('medium', 0)}</b>\n"
        f"Информационных: <b>{sev.get('info', 0)}</b>"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


SIM_CASES = {
    "sql": ("Высокий", "Попытка SQL-инъекции", "union select ...", "Запрос отклонён, инцидент зарегистрирован."),
    "xss": ("Высокий", "Попытка XSS/JS-инъекции", "<script>alert(1)</script>", "Контент классифицирован как опасный и заблокирован."),
    "spam": ("Средний", "Флуд/abuse-активность", "20 сообщений за короткий интервал", "Антиспам выдал временную блокировку."),
    "bruteforce": ("Высокий", "Подбор секретного кода", "5 неудачных попыток подряд", "Риск-профиль повышен, событие передано в журнал."),
    "admin": ("Высокий", "Попытка эскалации привилегий", "обращение к /dashboard без прав", "Доступ отклонён, доступ к админ-функциям не предоставлен."),
    "leak": ("Критический", "Утечка секрета", "обнаружено значение, похожее на токен", "Требуется ротация секрета и отзыв токена."),
}


async def simulate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    if not context.args:
        await update.effective_message.reply_text("Использование: /simulate sql|xss|spam|bruteforce|admin|leak")
        return
    kind = context.args[0].lower()
    if kind not in SIM_CASES:
        await update.effective_message.reply_text("Неизвестный сценарий. Доступные: sql, xss, spam, bruteforce, admin, leak")
        return
    level, title, evidence, response = SIM_CASES[kind]
    severity_map = {"Средний": "medium", "Высокий": "high", "Критический": "high"}
    log_event(update.effective_user.id, f"simulate_{kind}", severity_map.get(level, "info"), evidence)
    create_incident(update.effective_user.id, title, evidence, severity_map.get(level, "info"), response)
    text = (
        f"<b>Симуляция: {html.escape(title)}</b>\n"
        f"Критичность: <b>{level}</b>\n"
        f"Индикатор: <code>{html.escape(evidence)}</code>\n"
        f"Реакция: {html.escape(response)}"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def demo_attack(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    steps = [
        "🔎 Обнаружена разведка: последовательность нетипичных запросов.",
        "⚠️ Обнаружена попытка эскалации привилегий.",
        "🚨 Зафиксирован возможный brute force по проверочному коду.",
        "🛡 Контрмера: антиспам и блокировка подозрительных действий активированы.",
        "📁 Инцидент сформирован, журнал обновлён, риск-профиль повышен.",
    ]
    for step in steps:
        await update.effective_message.reply_text(step)
        await asyncio.sleep(0.6)
    log_event(update.effective_user.id, "demo_attack", "high", "Интерактивная демонстрация цепочки атаки")
    create_incident(update.effective_user.id, "Демонстрационный сценарий атаки", "Показана цепочка разведка → эскалация → brute force → блокировка.", "high", "Обучающая демонстрация завершена.")


async def red(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Red Team</b>\n"
        "Взгляд атакующего:\n"
        "• искать открытый токен;\n"
        "• проверять наличие служебных команд;\n"
        "• использовать вредоносный ввод;\n"
        "• подбирать код/пароль;\n"
        "• инициировать flood и abuse."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def blue(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Blue Team</b>\n"
        "Взгляд защитника:\n"
        "• хранить секреты вне кода;\n"
        "• ограничивать админ-доступ по ID и PIN;\n"
        "• анализировать ввод и включать IDS;\n"
        "• логировать события и инциденты;\n"
        "• ротировать секреты при признаках утечки."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def soc(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    users = count_rows("users")
    incidents = count_rows("incidents")
    events = count_rows("events")
    sev = severity_counts()
    text = (
        "<b>SOC-панель</b>\n"
        f"Пользователей: <b>{users}</b>\n"
        f"Событий: <b>{events}</b>\n"
        f"Инцидентов: <b>{incidents}</b>\n"
        f"High: <b>{sev.get('high', 0)}</b> | Medium: <b>{sev.get('medium', 0)}</b> | Info: <b>{sev.get('info', 0)}</b>\n"
        f"Последняя активность: <b>{now_iso()}</b>"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    if not await is_admin(update, context):
        increment_user_field(update.effective_user.id, "denied_access_count")
        log_event(update.effective_user.id, "admin_denied", "high", "Попытка доступа к админ-панели без прав")
        create_incident(update.effective_user.id, "Попытка доступа к админ-панели", "Пользователь без прав обратился к административной функции.", "high", "Доступ отклонён, событие записано.")
        await maybe_alert_admin(context, f"🚨 Попытка доступа к /admin от пользователя {update.effective_user.id}")
        await update.effective_message.reply_text("⛔ Нет прав. Попытка зафиксирована.")
        return
    context.user_data["admin_pending"] = True
    await update.effective_message.reply_text("Введите /admin_login <PIN> для второго этапа подтверждения.")


async def admin_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.effective_message.reply_text("⛔ Нет прав.")
        return
    if not context.user_data.get("admin_pending"):
        await update.effective_message.reply_text("Сначала используй /admin")
        return
    pin = " ".join(context.args).strip()
    cfg: Config = context.application.bot_data["config"]
    if pin != cfg.admin_pin:
        log_event(update.effective_user.id, "admin_pin_fail", "high", "Неверный PIN администратора")
        await update.effective_message.reply_text("❌ Неверный PIN.")
        return
    context.user_data["admin_verified"] = True
    context.user_data["admin_pending"] = False
    log_event(update.effective_user.id, "admin_login_success", "info", "Администратор успешно прошёл двухшаговый вход")
    await update.effective_message.reply_text("✅ Админ-доступ подтверждён. Доступны /dashboard, /logs, /incident, /report, /report_html, /chart_attacks")


async def require_admin_verified(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not await is_admin(update, context):
        await update.effective_message.reply_text("⛔ Команда только для администратора.")
        return False
    if not context.user_data.get("admin_verified"):
        await update.effective_message.reply_text("🔐 Сначала выполни двухшаговый вход: /admin → /admin_login <PIN>")
        return False
    return True


async def dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    users = count_rows("users")
    events = count_rows("events")
    incidents = count_rows("incidents")
    with get_conn() as conn:
        top = conn.execute(
            "SELECT telegram_id, suspicious_count, brute_force_count, honeypot_count FROM users ORDER BY (suspicious_count + brute_force_count + honeypot_count) DESC LIMIT 5"
        ).fetchall()
    lines = [
        "<b>Административная панель</b>",
        f"Пользователи: <b>{users}</b>",
        f"События: <b>{events}</b>",
        f"Инциденты: <b>{incidents}</b>",
        "\n<b>Топ риск-профилей</b>",
    ]
    if top:
        for row in top:
            score = row["suspicious_count"] * 10 + row["brute_force_count"] * 15 + row["honeypot_count"] * 20
            lines.append(f"• {row['telegram_id']} — скоринг {score}")
    else:
        lines.append("• данных пока нет")
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def logs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    rows = recent_events(12)
    if not rows:
        await update.effective_message.reply_text("Журнал пока пуст.")
        return
    chunks = ["<b>Последние события</b>"]
    for row in rows:
        chunks.append(
            f"• #{row['id']} [{row['severity']}] {html.escape(row['event_type'])} | user={row['telegram_id']} | {html.escape(row['created_at'])}\n  {html.escape(row['details'])}"
        )
    await update.effective_message.reply_text("\n".join(chunks), parse_mode=ParseMode.HTML)


async def incident(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    arg = context.args[0].lower() if context.args else "latest"
    with get_conn() as conn:
        if arg == "latest":
            row = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        elif arg.isdigit():
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (int(arg),)).fetchone()
        else:
            row = None
    if not row:
        await update.effective_message.reply_text("Инцидент не найден.")
        return
    text = (
        f"<b>Карточка инцидента #{row['id']}</b>\n"
        f"Время: {html.escape(row['created_at'])}\n"
        f"User: {row['telegram_id']}\n"
        f"Заголовок: {html.escape(row['title'])}\n"
        f"Критичность: {html.escape(row['severity'])}\n"
        f"Суть: {html.escape(row['summary'])}\n"
        f"Реакция: {html.escape(row['response'])}"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def case_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    target = context.args[0].lower() if context.args else "latest"
    with get_conn() as conn:
        if target == "latest":
            row = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        elif target == "user" and len(context.args) > 1 and context.args[1].isdigit():
            row = conn.execute(
                "SELECT * FROM incidents WHERE telegram_id = ? ORDER BY id DESC LIMIT 1",
                (int(context.args[1]),),
            ).fetchone()
        else:
            row = None
    if not row:
        await update.effective_message.reply_text("Кейс не найден. Использование: /case latest или /case user <id>")
        return
    text = (
        f"<b>Форензика / Incident Case #{row['id']}</b>\n"
        f"Субъект: {row['telegram_id']}\n"
        f"Дата: {html.escape(row['created_at'])}\n"
        f"Событие: {html.escape(row['title'])}\n"
        f"Описание: {html.escape(row['summary'])}\n"
        f"Ответ системы: {html.escape(row['response'])}\n"
        "Статус: зарегистрировано в хранилище инцидентов и доступно для отчётности."
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


def build_report_text() -> str:
    users = count_rows("users")
    events = count_rows("events")
    incidents = count_rows("incidents")
    ev = event_type_counts()
    sev = severity_counts()
    lines = [
        f"{APP_NAME} — сводный отчёт",
        f"Дата формирования: {now_iso()}",
        f"Пользователи: {users}",
        f"События: {events}",
        f"Инциденты: {incidents}",
        "",
        "Распределение по severity:",
    ]
    for key, value in sev.items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("Наиболее частые типы событий:")
    for key, value in ev.most_common(10):
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("Рекомендации:")
    lines.extend([
        "- Ротировать BOT_TOKEN при признаках утечки.",
        "- Использовать отдельную среду для хранения отчётов и базы.",
        "- Ужесточить политику админ-доступа и контролировать PIN.",
        "- Анализировать brute force и подозрительный ввод по журналам.",
    ])
    return "\n".join(lines)


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    await update.effective_message.reply_text(f"<pre>{html.escape(build_report_text())}</pre>", parse_mode=ParseMode.HTML)


async def report_html(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    report_text = build_report_text().splitlines()
    rows = recent_incidents(10)
    incident_html = "".join(
        f"<tr><td>{r['id']}</td><td>{html.escape(r['created_at'])}</td><td>{html.escape(r['title'])}</td><td>{html.escape(r['severity'])}</td></tr>"
        for r in rows
    ) or "<tr><td colspan='4'>Нет данных</td></tr>"
    html_doc = f"""
    <html><head><meta charset='utf-8'><title>{APP_NAME} Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 30px; }}
    h1, h2 {{ color: #16324f; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    td, th {{ border: 1px solid #999; padding: 8px; font-size: 14px; }}
    .box {{ background: #f4f7fb; padding: 16px; border-radius: 12px; }}
    </style></head><body>
    <h1>{APP_NAME}</h1>
    <div class='box'><pre>{html.escape(chr(10).join(report_text))}</pre></div>
    <h2>Последние инциденты</h2>
    <table><tr><th>ID</th><th>Дата</th><th>Заголовок</th><th>Severity</th></tr>{incident_html}</table>
    </body></html>
    """
    path = REPORTS_DIR / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path.write_text(html_doc, encoding="utf-8")
    await update.effective_message.reply_document(InputFile(path.open("rb"), filename=path.name))


async def chart_attacks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_admin_verified(update, context):
        return
    counts = event_type_counts()
    if not counts:
        await update.effective_message.reply_text("Недостаточно данных для графика.")
        return
    labels = list(counts.keys())[:10]
    values = [counts[l] for l in labels]
    fig = plt.figure(figsize=(10, 5))
    plt.bar(labels, values)
    plt.xticks(rotation=35, ha="right")
    plt.ylabel("Количество")
    plt.title("События безопасности по типам")
    plt.tight_layout()
    path = REPORTS_DIR / f"attacks_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    await update.effective_message.reply_photo(InputFile(path.open("rb"), filename=path.name), caption="График распределения событий безопасности")


async def honeypot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    increment_user_field(update.effective_user.id, "honeypot_count")
    log_event(update.effective_user.id, "honeypot_trigger", "high", f"Сработала honeypot-команда /{update.message.text.split()[0].lstrip('/')}")
    create_incident(
        update.effective_user.id,
        "Сработала honeypot-команда",
        f"Пользователь обратился к ловушечной команде {update.message.text.split()[0]}",
        "high",
        "Событие трактуется как разведка или попытка злоупотребления служебными командами.",
    )
    await maybe_alert_admin(context, f"🚨 Honeypot: пользователь {update.effective_user.id} вызвал {update.message.text.split()[0]}")
    await update.effective_message.reply_text("⛔ Команда недоступна. Событие классифицировано как разведывательная активность и записано в журнал.")


async def profile(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_user(update.effective_user)
    stats = get_user_stats(update.effective_user.id)
    text = (
        "<b>Профиль пользователя</b>\n"
        f"Telegram ID: <code>{update.effective_user.id}</code>\n"
        f"Дата регистрации: {html.escape(str(stats.get('registered_at', '—')))}\n"
        f"Подозрительный ввод: {stats.get('suspicious_count', 0)}\n"
        f"Denied access: {stats.get('denied_access_count', 0)}\n"
        f"Brute force: {stats.get('brute_force_count', 0)}\n"
        f"Honeypot: {stats.get('honeypot_count', 0)}"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


async def callback_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if query.data == "menu_dashboard":
        await soc(update, context)
    elif query.data == "menu_threats":
        await threats(update, context)
    elif query.data == "menu_architecture":
        await architecture(update, context)
    elif query.data == "menu_check":
        await query.message.reply_text("Используй /check <текст>. Например: /check <script>alert(1)</script>")
    elif query.data == "menu_simulate":
        await query.message.reply_text("Используй /simulate sql|xss|spam|bruteforce|admin|leak")
    elif query.data == "menu_ids":
        await ids(update, context)
    elif query.data == "menu_model":
        await threat_model(update, context)
    elif query.data == "menu_report":
        await report(update, context)


async def generic_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message or not update.effective_user:
        return
    if await anti_spam(update, context):
        return
    ensure_user(update.effective_user)
    text = update.effective_message.text or ""
    severity, findings = analyze_text_security(text)
    if severity in {"Средний", "Высокий"}:
        increment_user_field(update.effective_user.id, "suspicious_count")
        sev = "medium" if severity == "Средний" else "high"
        log_event(update.effective_user.id, "message_anomaly", sev, "; ".join(findings))
        if severity == "Высокий":
            create_incident(update.effective_user.id, "Автоматически обнаружена аномалия", ", ".join(findings), "high", "Пользователю выдано предупреждение, событие зарегистрировано.")
            await maybe_alert_admin(context, f"🚨 IDS: высокорисковое сообщение от {update.effective_user.id}: {', '.join(findings)}")
            await update.effective_message.reply_text("⚠️ IDS: сообщение похоже на опасное. Сработали правила обнаружения угроз.")


async def post_init(application: Application) -> None:
    commands = [
        BotCommand("start", "запуск бота"),
        BotCommand("menu", "кнопочное меню"),
        BotCommand("help", "список команд"),
        BotCommand("info", "о проекте"),
        BotCommand("architecture", "архитектура защищённого бота"),
        BotCommand("threats", "угрозы для Telegram-ботов"),
        BotCommand("threat_model", "модель угроз"),
        BotCommand("security", "меры защиты"),
        BotCommand("policies", "политика безопасной эксплуатации"),
        BotCommand("profile", "профиль пользователя"),
        BotCommand("check", "анализ пользовательского ввода"),
        BotCommand("verify", "проверка секретного кода"),
        BotCommand("risk", "скоринг риска пользователя"),
        BotCommand("ids", "статус IDS"),
        BotCommand("simulate", "симуляция атаки"),
        BotCommand("demo_attack", "цепочка атаки в реальном времени"),
        BotCommand("red", "перспектива атакующего"),
        BotCommand("blue", "перспектива защитника"),
        BotCommand("soc", "центр мониторинга"),
        BotCommand("admin", "инициализация админ-входа"),
        BotCommand("admin_login", "второй этап админ-входа"),
        BotCommand("dashboard", "административная панель"),
        BotCommand("logs", "журнал событий"),
        BotCommand("incident", "карточка инцидента"),
        BotCommand("case", "форензика по инциденту"),
        BotCommand("report", "текстовый отчёт"),
        BotCommand("report_html", "HTML-отчёт файлом"),
        BotCommand("chart_attacks", "график атак"),
    ]
    await application.bot.set_my_commands(commands)


async def main() -> None:
    init_db()
    config = load_config()

    application = (
        Application.builder()
        .token(config.bot_token)
        .rate_limiter(AIORateLimiter())
        .post_init(post_init)
        .build()
    )
    application.bot_data["config"] = config

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_cmd))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("info", info))
    application.add_handler(CommandHandler("architecture", architecture))
    application.add_handler(CommandHandler("threats", threats))
    application.add_handler(CommandHandler("threat_model", threat_model))
    application.add_handler(CommandHandler("security", security))
    application.add_handler(CommandHandler("policies", policies))
    application.add_handler(CommandHandler("profile", profile))
    application.add_handler(CommandHandler("check", check_cmd))
    application.add_handler(CommandHandler("verify", verify))
    application.add_handler(CommandHandler("risk", risk))
    application.add_handler(CommandHandler("ids", ids))
    application.add_handler(CommandHandler("simulate", simulate))
    application.add_handler(CommandHandler("demo_attack", demo_attack))
    application.add_handler(CommandHandler("red", red))
    application.add_handler(CommandHandler("blue", blue))
    application.add_handler(CommandHandler("soc", soc))
    application.add_handler(CommandHandler("admin", admin))
    application.add_handler(CommandHandler("admin_login", admin_login))
    application.add_handler(CommandHandler("dashboard", dashboard))
    application.add_handler(CommandHandler("logs", logs_cmd))
    application.add_handler(CommandHandler("incident", incident))
    application.add_handler(CommandHandler("case", case_cmd))
    application.add_handler(CommandHandler("report", report))
    application.add_handler(CommandHandler("report_html", report_html))
    application.add_handler(CommandHandler("chart_attacks", chart_attacks))

    for hp in ["root", "token", "database", "admin_full", "config_dump", "secret_env"]:
        application.add_handler(CommandHandler(hp, honeypot))

    application.add_handler(CallbackQueryHandler(callback_menu))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, generic_message))

    logger.info("Starting %s", APP_NAME)
    await application.run_polling(close_loop=False)


if __name__ == "__main__":
    asyncio.run(main())
