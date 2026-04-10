# SafeGate Research Bot

Telegram-бот для исследовательской работы по теме защиты информации в Telegram-ботах.

## Что умеет
- архитектура и модель угроз Telegram-бота;
- анализ опасного ввода;
- симуляции атак и живой demo-сценарий;
- IDS-панель и SOC-панель;
- двухшаговый вход администратора;
- журнал событий и карточки инцидентов;
- HTML-отчёт и график событий безопасности;
- honeypot-команды для выявления разведки.

## Команды
`/start`, `/menu`, `/help`, `/info`, `/architecture`, `/threats`, `/threat_model`, `/security`, `/policies`, `/profile`, `/check`, `/verify`, `/risk`, `/ids`, `/simulate`, `/demo_attack`, `/red`, `/blue`, `/soc`, `/admin`, `/admin_login`, `/dashboard`, `/logs`, `/incident`, `/case`, `/report`, `/report_html`, `/chart_attacks`.

## Установка
```bash
python -m pip install -r requirements.txt
python bot.py
```

## Honeypot-команды
`/root`, `/token`, `/database`, `/admin_full`, `/config_dump`, `/secret_env`

## Примечание
Токен помещён в `.env` только для готового запуска. После проверки лучше перевыпустить токен через `@BotFather`.
