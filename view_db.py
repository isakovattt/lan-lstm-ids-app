import os
import psycopg
from datetime import datetime

def view_all():
    print("🔍 === ИСТОРИЯ АНАЛИЗА ===\n")
    
    database_url = os.environ.get('IDS_DATABASE_URL', 'postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db')
    conn = psycopg.connect(database_url)
    c = conn.cursor()
    
    c.execute("""SELECT timestamp, anomaly_prob, is_anomaly, message 
                 FROM results ORDER BY id DESC LIMIT 50""")
    rows = c.fetchall()
    
    if not rows:
        print("Пока нет записей. Запусти агент и подожди 20-30 секунд.")
    else:
        for row in rows:
            time_str = row[0][:19].replace("T", " ")
            status = "🔴 АНОМАЛИЯ" if row[2] else "🟢 Норма"
            print(f"[{time_str}]  Вероятность: {row[1]:.3f}  {status}")
            print(f"    → {row[3]}")
            print("-" * 80)
    
    conn.close()
    
    # Показываем аномальные дампы
    print("\n📁 === СОХРАНЁННЫЕ АНОМАЛЬНЫЕ ДАМПЫ ===\n")
    dump_dir = "dumps"
    if os.path.exists(dump_dir):
        files = [f for f in os.listdir(dump_dir) if f.endswith(".pcap")]
        if files:
            for f in sorted(files, reverse=True):
                size = os.path.getsize(os.path.join(dump_dir, f)) / 1024
                print(f"📄 {f}  ({size:.1f} KB)")
        else:
            print("Пока нет сохранённых дампов.")
    else:
        print("Папка dumps не найдена.")

if __name__ == "__main__":
    view_all()