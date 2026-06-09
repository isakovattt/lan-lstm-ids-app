
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

## Запуск

1. Запустить сервер:

```bash
cd /Users/deux/Documents/nei/lan_lstm_ids_app
source .venv/bin/activate
python server.py
```

или двойным кликом по `run_server.command`.

2. Запустить desktop agent в другом окне:

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

