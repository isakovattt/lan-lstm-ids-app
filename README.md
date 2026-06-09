

Приложение для обнаружения аномалий в локальной сети с помощью обученной LSTM-модели.

## Состав

- `server.py` — Flask-сервер IDS.
- `agent.py` — desktop-агент для перехвата пакетов и просмотра инцидентов.
- `agent_client.py` — консольный агент.
- `lstm_runtime.py` — подготовка признаков и запуск LSTM inference.
- `model_bundle/` — обученная модель и файлы, нужные для её работы.

## Модель

Приложение использует модель:

```text
model_bundle/final_best_lan_lstm_smooth_90.keras
```

Для inference также нужны:

- `model_bundle/scaler_params.npz`
- `model_bundle/feature_columns.json`

## Датасет

Датасет на Kaggle:

https://www.kaggle.com/datasets/quarantedeux42/lan-anomaly-lstm-moderate-hard-dataset

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск

Сервер:

```bash
python server.py
```

Desktop agent:

```bash
python agent.py
```

Консольный agent:

```bash
python agent_client.py
```
