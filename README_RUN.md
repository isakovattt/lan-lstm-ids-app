# LAN LSTM IDS App

Финальная папка приложения: `/Users/deux/Documents/nei/lan_lstm_ids_app`

## Что внутри

- `server.py` — Flask-сервер с подключенной LSTM.
- `agent.py` — desktop IDS GUI для перехвата, просмотра пакетов и инцидентов.
- `agent_client.py` — консольный агент для конечного устройства.
- `lstm_runtime.py` — подготовка признаков и inference через LSTM.
- `model_bundle/` — сохраненная последняя модель, scaler, графики, метрики.
- `.venv/` — виртуальное окружение с зависимостями.
- `run_server.command` — запуск сервера.
- `run_desktop_agent.command` — запуск desktop GUI.
- `run_console_agent.command` — запуск консольного агента.


## PostgreSQL

Сервер больше не использует локальный `server.db` как рабочую БД. Подключение берётся из переменной окружения:

```bash
export IDS_DATABASE_URL="postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db"
```

Перед первым запуском создайте пользователя и базу в PostgreSQL, затем установите зависимости:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
pip install -r requirements.txt
```

Если нужно перенести старые данные из SQLite `server.db` в PostgreSQL:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
export IDS_DATABASE_URL="postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db"
python migrate_sqlite_to_postgres.py
```

## Запуск

1. Запустить сервер:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
python server.py
```

или двойным кликом по `run_server.command`.

2. Запустить desktop IDS agent в другом окне:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
python agent.py
```

или двойным кликом по `run_desktop_agent.command`.

3. Если нужен консольный endpoint-agent:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
python agent_client.py
```

или `run_console_agent.command`.

## Важно

- Сервер работает на `http://127.0.0.1:5050`, потому что порт 5000 на macOS часто занят AirPlay/ControlCenter.
- Для реального перехвата пакетов Scapy на macOS может потребовать права доступа к `/dev/bpf*`. Если перехват не стартует, запускай агент через терминал с повышенными правами macOS:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
sudo .venv/bin/python agent.py
```

или для консольного агента:

```bash
sudo .venv/bin/python agent_client.py
```

## Проверка модели

Когда сервер запущен:

```bash
curl http://127.0.0.1:5050/model_status
```

`available` должен быть `true`, `engine` в результатах `/analyze` должен быть `lstm`.
