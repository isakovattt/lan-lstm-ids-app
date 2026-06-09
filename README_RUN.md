# LAN LSTM IDS App

Приложение для обнаружения аномалий в локальной сети с помощью обученной LSTM-модели.

## Что внутри

- `server.py` — Flask-сервер с подключенной LSTM-моделью.
- `agent.py` — desktop IDS GUI для перехвата, просмотра пакетов и инцидентов.
- `agent_client.py` — консольный агент для конечного устройства.
- `lstm_runtime.py` — подготовка признаков и inference через LSTM.
- `model_bundle/` — обученная модель, scaler, список признаков, графики и метрики.
- `run_server.command` — запуск сервера.
- `run_desktop_agent.command` — запуск desktop GUI.
- `run_console_agent.command` — запуск консольного агента.

## Обученная нейронная сеть

Да, обученная нейронная сеть загружена в репозиторий в папке `model_bundle/`:

- `best_lan_lstm_smooth_90.keras`
- `final_best_lan_lstm_smooth_90.keras`
- `scaler_params.npz`
- `feature_columns.json`
- `run_summary.json`

## Датасет

Датасет для обучения и проверки модели находится на Kaggle:

<https://www.kaggle.com/datasets/quarantedeux42/lan-anomaly-lstm-moderate-hard-dataset>

В GitHub-репозитории хранится приложение и обученный `model_bundle/`. Рабочие дампы пакетов, локальная БД, виртуальное окружение и операторская разметка не загружаются.

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## PostgreSQL

Сервер использует PostgreSQL. Подключение берётся из переменной окружения:

```bash
export IDS_DATABASE_URL="postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db"
```

Если нужно перенести старые данные из SQLite `server.db` в PostgreSQL:

```bash
export IDS_DATABASE_URL="postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db"
python migrate_sqlite_to_postgres.py
```

## Запуск

1. Запустить сервер:

```bash
python server.py
```

или двойным кликом по `run_server.command`.

2. Запустить desktop IDS agent в другом окне:

```bash
python agent.py
```

или двойным кликом по `run_desktop_agent.command`.

3. Если нужен консольный endpoint-agent:

```bash
python agent_client.py
```

или `run_console_agent.command`.

## Проверка модели

Когда сервер запущен:

```bash
curl http://127.0.0.1:5050/model_status
```

`available` должен быть `true`, а `engine` в результатах `/analyze` должен быть `lstm`.

## Важно

- Сервер работает на `http://127.0.0.1:5050`, потому что порт 5000 на macOS часто занят AirPlay/ControlCenter.
- Для реального перехвата пакетов Scapy на macOS может потребовать права доступа к `/dev/bpf*`.
- Если перехват не стартует, запускайте агента с повышенными правами macOS:

```bash
sudo .venv/bin/python agent.py
```
