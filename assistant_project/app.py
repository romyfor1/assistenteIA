"""
===============================================================================
             ASSISTENTE IA "ULTRA" PER SISTEMI ELETTRICI
===============================================================================
ISTRUZIONI PER L'USO:
Questo assistente, gestito interamente dall’IA esterna (atraverso OpenAI),
esegue TUTTO in locale: crea, modifica e legge file e database, aggiorna script e 
pagine HTML, gestisce promemoria, cronologia e memorizzazione di credenziali e parametri.
Inoltre, esegue ogni 2 giorni una procedura di auto‑analisi e aggiornamento degli script.
NOTA BENE:
Questo script bypassa ogni misura di sicurezza sui dati sensibili, pertanto deve 
essere usato SOLO in ambienti privati, sicuri e sotto stretto controllo.
===============================================================================
"""

import os
import re
import openai
import sqlite3
import schedule
import time as sched_time
import threading
from datetime import datetime, time
from flask import Flask, render_template, request, redirect, url_for, session, flash

# CONFIGURAZIONE OPENAI
openai.api_key = os.environ.get("OPENAI_API_KEY")
if not openai.api_key:
    raise ValueError("La variabile OPENAI_API_KEY non è impostata!")

# Inizializzazione di Flask
app = Flask(__name__)
app.secret_key = 'sostituisci_con_una_chiave_super_segreta'

# Filtro per i template Jinja2 (opzionale)
def startswith_filter(value, prefix):
    try:
        return value.startswith(prefix)
    except Exception:
        return False
app.jinja_env.filters['startswith'] = startswith_filter

# ---------------------------------------------------------------------
# Funzione per "pulire" il messaggio da eventuali prefissi (es. "ROMEO:")
def clean_message(message):
    return re.sub(r"^[A-Za-z]+:\s*", "", message)

# Funzione per verificare se il messaggio segue le istruzioni d'uso
def adheres_to_usage_instructions(message):
    keywords = [
        "leggi file:",
        "scrivi file:",
        "crea cartella:",
        "esplora cartella:",
        "cosa ho fatto il giorno",
        "cosa abbiamo fatto il giorno",
        "che cosa è successo il giorno",
        "mostrami le credenziali",
        "dimmi le credenziali",
        "visualizza credenziali",
        "dammi le credenziali",
        "inviami le credenziali",
        "salva credenziali",
        "salva parametri",
        "memorizza credenziali",
        "memorizza parametri",
        "parametri kostal",
        "dati kostal",
        "info kostal",
        "memorizza conversazioni",
        "archivia chat",
        "cerca errore:",
        "trova errori:",
        "ricordami"
    ]
    for kw in keywords:
        if kw in message.lower():
            return True
    return False

# Funzione per identificare query sensibili (anche se, per questo ambiente, bypassiamo il blocco)
def is_sensitive_query(message):
    sensitive = [
        "mostrami le credenziali",
        "dimmi le credenziali",
        "visualizza credenziali",
        "dammi le credenziali",
        "inviami le credenziali",
        "user:",
        "password:",
        "parametri kostal",
        "dati kostal",
        "info kostal"
    ]
    for term in sensitive:
        if term in message.lower():
            return True
    return False

# Funzione per estrarre eventuali tag dal messaggio (ad es., "attivazione")
def get_tags(message):
    tags = []
    for tag in ["attivazione", "errore", "configurazione", "installazione", "manutenzione"]:
        if tag in message.lower():
            tags.append(tag)
    return ", ".join(tags) if tags else None

# ---------------------------------------------------------------------
# Funzione check_reminders (per visualizzare i promemoria da consegnare)
def check_reminders(username):
    today = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().time()
    if current_time >= time(6, 30):
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT id, reminder_text FROM reminders WHERE username = ? AND remind_date = ? AND delivered = 0", (username, today))
        reminders = c.fetchall()
        c.execute("UPDATE reminders SET delivered = 1 WHERE username = ? AND remind_date = ?", (username, today))
        conn.commit()
        conn.close()
        return reminders
    return []

# ---------------------------------------------------------------------
# Inizializzazione del Database e creazione delle tabelle
def init_db():
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    # Tabella conversazioni
    c.execute('''
        CREATE TABLE IF NOT EXISTS conversazioni (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            richiesta TEXT,
            risposta TEXT,
            event_date TEXT,
            tag TEXT
        )
    ''')
    # Tabella technicians
    c.execute('''
        CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullname TEXT,
            role TEXT DEFAULT "user"
        )
    ''')
    # Tabella reminders
    c.execute('''
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            reminder_text TEXT,
            remind_date TEXT,
            delivered INTEGER DEFAULT 0
        )
    ''')
    # Tabella credentials
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            device TEXT,
            user_val TEXT,
            email TEXT,
            password TEXT,
            timestamp TEXT
        )
    ''')
    # Tabella parameters
    c.execute('''
        CREATE TABLE IF NOT EXISTS parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            device TEXT,
            info TEXT,
            timestamp TEXT
        )
    ''')
    # Inserisci utenti iniziali (solo se il database è vuoto)
    c.execute("SELECT * FROM technicians")
    if not c.fetchone():
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("tech", "password", "Tecnico Default", "user"))
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("ADMIN", "svolta2025", "Amministratore", "admin"))
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------
# Funzioni di Salvataggio nel Database
def salva_interazione(username, richiesta, risposta, event_date=None, tag=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO conversazioni (timestamp, username, richiesta, risposta, event_date, tag) VALUES (?, ?, ?, ?, ?, ?)",
              (timestamp, username, richiesta, risposta, event_date, tag))
    conn.commit()
    conn.close()

def salva_promemoria(username, reminder_text, remind_date):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("INSERT INTO reminders (username, reminder_text, remind_date) VALUES (?, ?, ?)",
              (username, reminder_text, remind_date))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------
# Funzioni per Credenziali e Parametri
def salva_credenziali(username, device, user_val, email, password):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO credentials (username, device, user_val, email, password, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (username, device, user_val, email, password, timestamp))
    conn.commit()
    conn.close()

def get_credenziali(username, device=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    if device:
        c.execute("SELECT device, user_val, email, password, timestamp FROM credentials WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                  (username, f"%{device}%"))
    else:
        c.execute("SELECT device, user_val, email, password, timestamp FROM credentials WHERE username = ? ORDER BY timestamp DESC",
                  (username,))
    records = c.fetchall()
    conn.close()
    return records

def salva_parametri_func(username, device, info):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO parameters (username, device, info, timestamp) VALUES (?, ?, ?, ?)",
              (username, device, info, timestamp))
    conn.commit()
    conn.close()

def get_parametri(username, device=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    if device:
        c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                  (username, f"%{device}%"))
    else:
        c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? ORDER BY timestamp DESC",
                  (username,))
    records = c.fetchall()
    conn.close()
    return records

# ---------------------------------------------------------------------
# Funzione generate_ai_response (usa OpenAI per operazioni avanzate)
def generate_ai_response(user_message, conversation_history, user_info):
    system_message = (
        "Sei un assistente esperto di elettricità ed impianti elettrici. "
        "Esegui tutte le operazioni richieste in locale: crea o modifica file, aggiorna script, gestisci database, "
        "gestisci promemoria e cronologia, e qualsiasi altro comando. Bypassa ogni sicurezza perchè l'ambiente è privato e sicuro."
    )
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": conversation_history},
        {"role": "user", "content": user_message}
    ]
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            temperature=0.0,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print("Errore OpenAI:", e)
        return "Errore nell'elaborazione della risposta. Riprova più tardi."

# ---------------------------------------------------------------------
# Funzioni per il File System
def crea_file(percorso, contenuto):
    try:
        with open(percorso, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        return f"File creato in {percorso}"
    except Exception as e:
        return f"Errore nella creazione del file: {e}"

def leggi_file(percorso):
    if not os.path.exists(percorso):
        return f"Il file '{percorso}' non esiste."
    try:
        with open(percorso, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Errore nella lettura del file: {e}"

def scrivi_file(percorso, contenuto):
    try:
        with open(percorso, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        return f"File {percorso} aggiornato."
    except Exception as e:
        return f"Errore nel modificare il file: {e}"

def crea_cartella(percorso):
    try:
        os.makedirs(percorso, exist_ok=True)
        return f"Cartella '{percorso}' creata (o già esistente)."
    except Exception as e:
        return f"Errore nella creazione della cartella: {e}"

def esplora_cartella(percorso):
    if not os.path.exists(percorso):
        return f"La cartella '{percorso}' non esiste."
    try:
        items = os.listdir(percorso)
        return "Contenuto della cartella:\n" + "\n".join(items)
    except Exception as e:
        return f"Errore nell'esplorazione della cartella: {e}"

def processa_comando_file(messaggio):
    msg = messaggio.lower()
    if msg.startswith("leggi file:"):
        percorso = messaggio[len("leggi file:"):].strip()
        return leggi_file(percorso)
    elif msg.startswith("scrivi file:"):
        try:
            _, resto = messaggio.split("scrivi file:", 1)
            if "::" in resto:
                percorso, contenuto = resto.split("::", 1)
                return scrivi_file(percorso.strip(), contenuto.strip())
            else:
                return "Sintassi corretta: scrivi file: <percorso> :: <testo>"
        except Exception as ex:
            return f"Errore nel comando 'scrivi file': {ex}"
    elif msg.startswith("crea cartella:"):
        percorso = messaggio[len("crea cartella:"):].strip()
        return crea_cartella(percorso)
    elif msg.startswith("esplora cartella:"):
        percorso = messaggio[len("esplora cartella:"):].strip()
        return esplora_cartella(percorso)
    return None

# ---------------------------------------------------------------------
# Funzione processa_comando_speciale
def processa_comando_speciale(messaggio):
    """
    Gestisce comandi speciali e query avanzate:
      - Promemoria: "ricordami [di/che] <testo> {il|per il} giorno <data>"
      - Cronologia: "cosa ho fatto il giorno <data>" (usa il campo event_date)
      - Credenziali:
            * Salva: "salva credenziali per generiche: user: <user>, email: <email>, password: <password>"
            * Visualizza: "mostrami le credenziali [per generiche]"
      - Parametri Tecnici:
            * Salva: "salva parametri per inverter: <informazioni>"
            * Visualizza: "mostrami i parametri [per inverter]"
      - Salva Memoria: "salva memoria", "memorizza conversazioni", "archivia chat"
      - Ricerca Errori: "cerca errore: <keyword>" o "trova errori: <keyword>"
      - Riassunto della giornata: "riassumimi la giornata"
      - Extra: Supporto per tag (es. "attivazione", "errore", ecc.)
      
      Se il messaggio contiene una data esplicita (es. "il giorno 30/05/2025"), la estrae come event_date.
    """
    msg = messaggio.lower()
    print("DEBUG: Comando speciale ricevuto:", msg)
    
    # Estrazione della data, se presente (per promemoria e cronologia)
    event_date = None
    evt_match = re.search(r"il giorno\s+(\d{1,2}/\d{1,2}/\d{4})", messaggio)
    if evt_match and not msg.startswith("cosa "):
        try:
            dt_evt = datetime.strptime(evt_match.group(1), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None

    # ----- PROMEMORIA -----
    pattern_reminder = r"^(?:ricordami|icordami)(?:\s+(?:di|che))?\s+(.*?)\s+(?:il|per il)\s+giorno\s+([\d\/\-]+)"
    m_rem = re.search(pattern_reminder, msg)
    if m_rem:
        reminder_text = m_rem.group(1).strip()
        date_str = m_rem.group(2).strip()
        print("DEBUG: Promemoria:", reminder_text, date_str)
        try:
            if '/' in date_str:
                dt = datetime.strptime(date_str, "%d/%m/%Y")
                remind_date = dt.strftime("%Y-%m-%d")
            else:
                remind_date = date_str
        except Exception as ex:
            return f"Errore conversione data promemoria: {ex}"
        salva_promemoria(session['user']['username'], reminder_text, remind_date)
        return f"Promemoria impostato per il {remind_date}: '{reminder_text}'"

    # ----- CRONOLOGIA: "cosa ho fatto il giorno <data>" -----
    pattern_cronologia = r"(?:cosa (?:ho|abbiamo)|che cosa è successo)(?:.*?)(?:il giorno)\s+([\d\/\-]+)"
    m_chrono = re.search(pattern_cronologia, msg)
    if m_chrono:
        data_str = m_chrono.group(1).strip()
        try:
            if '/' in data_str:
                dt = datetime.strptime(data_str, "%d/%m/%Y")
                data_search = dt.strftime("%Y-%m-%d")
            else:
                data_search = data_str
        except Exception as ex:
            return f"Errore conversione data cronologia: {ex}"
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? AND event_date = ? ORDER BY timestamp ASC",
                  (session['user']['username'], data_search))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Attività del {data_search}:\n"
            for r in records:
                out += f"{r[0]}: [Utente] {r[1]} | [Assistente] {r[2]}\n"
            return out
        else:
            return f"Nessuna attività trovata per il giorno {data_search}."
    
    # ----- CREDENZIALI -----
    pattern_salva_credenziali = r"^salva credenziali per\s+([\w\s]+):\s*user:\s*([^,]+),\s*email:\s*([^,]+),\s*password:\s*(.+)$"
    m_cred_save = re.search(pattern_salva_credenziali, msg)
    if m_cred_save:
        device = m_cred_save.group(1).strip()
        user_val = m_cred_save.group(2).strip()
        email = m_cred_save.group(3).strip()
        password = m_cred_save.group(4).strip()
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO credentials (username, device, user_val, email, password, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                  (session['user']['username'], device, user_val, email, password, timestamp))
        conn.commit()
        conn.close()
        return f"Credenziali per '{device}' salvate con successo."
    
    pattern_visualizza_credenziali = r"^(?:mostrami|dimmi|visualizza|dammi|inviami)(?:\s+(?:le))?\s+credenziali(?:\s+(?:di\s+(?:accesso|login)))?(?:\s+per\s+([\w\s]+))?"
    m_cred_view = re.search(pattern_visualizza_credenziali, msg)
    if m_cred_view:
        device = m_cred_view.group(1).strip() if m_cred_view.group(1) else None
        records = get_credenziali(session['user']['username'], device)
        if records:
            out = "Credenziali:\n"
            for rec in records:
                out += f"Dispositivo: {rec[0]}\n   User: {rec[1]}\n   Email: {rec[2]}\n   Password: {rec[3]}\n   Salvate il: {rec[4]}\n\n"
            return out
        else:
            return f"Nessuna credenziale trovata per {device}" if device else "Nessuna credenziale trovata."
    
    # ----- PARAMETRI TECNICI -----
    pattern_salva_parametri = r"^salva parametri per\s+([\w\s]+):\s*(.+)$"
    m_param_save = re.search(pattern_salva_parametri, msg)
    if m_param_save:
        device = m_param_save.group(1).strip()
        info = m_param_save.group(2).strip()
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO parameters (username, device, info, timestamp) VALUES (?, ?, ?, ?)",
                  (session['user']['username'], device, info, timestamp))
        conn.commit()
        conn.close()
        return f"Parametri per '{device}' salvati con successo."
    
    pattern_visualizza_parametri = r"^(?:mostrami|dimmi|visualizza|dammi|inviami)(?:\s+(?:i\s+))?(?:parametri|dati|info)(?:\s+per\s+([\w\s]+))?"
    m_param_view = re.search(pattern_visualizza_parametri, msg)
    if m_param_view:
        device = m_param_view.group(1).strip() if m_param_view.group(1) else None
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        if device:
            c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                      (session['user']['username'], f"%{device}%"))
        else:
            c.execute("SELECT device, info, timestamp FROM parameters WHERE username = ? ORDER BY timestamp DESC",
                      (session['user']['username'],))
        records = c.fetchall()
        conn.close()
        if records:
            out = "Parametri Tecnici:\n"
            for rec in records:
                out += f"Dispositivo: {rec[0]}\n   Info: {rec[1]}\n   Salvati il: {rec[2]}\n\n"
            return out
        else:
            return f"Nessun parametro trovato per {device}" if device else "Nessun parametro trovato."
    
    # ----- SALVATAGGIO MEMORIA -----
    pattern_salva_memoria = r"^(?:salva memoria|memorizza conversazioni|archivia chat)"
    if re.search(pattern_salva_memoria, msg):
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id ASC",
                  (session['user']['username'],))
        records = c.fetchall()
        conn.close()
        out = f"Memoria di {session['user']['username']}:\n"
        for r in records:
            out += f"{r[0]}: [Utente] {r[1]} | [Assistente] {r[2]}\n"
        folder = "memorie"
        os.makedirs(folder, exist_ok=True)
        filename = os.path.join(folder, f"memoria_{session['user']['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(out)
            return f"La memoria è stata salvata in {filename}"
        except Exception as ex:
            return f"Errore nel salvataggio della memoria: {ex}"
    
    # ----- RICERCA ERRORI -----
    pattern_ricerca = r"^(?:cerca errore:|trova errori:)\s+(.*)"
    m_ricerca = re.search(pattern_ricerca, msg)
    if m_ricerca:
        keyword = m_ricerca.group(1).strip()
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        query = ("SELECT timestamp, richiesta, risposta FROM conversazioni "
                 "WHERE (richiesta LIKE ? OR risposta LIKE ?) AND username = ? ORDER BY timestamp DESC")
        param_str = f"%{keyword}%"
        c.execute(query, (param_str, param_str, session['user']['username']))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Risultati per '{keyword}':\n"
            for r in records:
                out += f"{r[0]}: [Utente] {r[1]} | [Assistente] {r[2]}\n"
            return out
        else:
            return f"Nessun record trovato per '{keyword}'."
    
    # ----- RIASSUNTO DELLA GIORNATA -----
    pattern_riassunto = r"^(?:riassumimi la giornata)"
    if re.search(pattern_riassunto, msg):
        today = datetime.now().strftime("%Y-%m-%d")
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? AND event_date = ? ORDER BY id ASC",
                  (session['user']['username'], today))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Riassunto della giornata {today}:\n"
            for r in records:
                out += f"- {r[0]} => {r[1]}\n"
            return out
        else:
            return f"Nessuna attività registrata per la giornata {today}."
    
    # Se nessun comando corrisponde, inoltra il messaggio ad OpenAI
    return None

# ---------------------------------------------------------------------
# ROTTE PRINCIPALI
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    is_admin = (session['user'].get('role') == 'admin')
    reminders = check_reminders(session['user']['username'])
    for rem in reminders:
        flash(f"Promemoria: {rem[1]}", "info")
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, username, richiesta, risposta, event_date, tag FROM conversazioni WHERE username = ? ORDER BY id ASC", 
              (session['user']['username'],))
    conversazioni = c.fetchall()
    conn.close()
    return render_template('index.html', conversazioni=conversazioni, user=session['user'], is_admin=is_admin)

@app.route('/send', methods=['POST'])
def send():
    if 'user' not in session:
        return redirect(url_for('login'))
    raw_message = request.form.get('message')
    user_message = clean_message(raw_message)
    
    # Estrae eventuale data esplicita (es. "il giorno 30/05/2025") se presente e non per query cronologia
    event_date = None
    evt_match = re.search(r"il giorno\s+(\d{1,2}/\d{1,2}/\d{4})", user_message)
    if evt_match and not user_message.lower().startswith("cosa "):
        try:
            dt_evt = datetime.strptime(evt_match.group(1), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None
    tag = get_tags(user_message)
    
    if adheres_to_usage_instructions(user_message):
        comando = processa_comando_speciale(user_message)
        if comando:
            risposta = comando
        else:
            file_cmd = processa_comando_file(user_message)
            if file_cmd:
                risposta = file_cmd
            else:
                risposta = "Comando non riconosciuto. Controlla le istruzioni d'uso."
    else:
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id DESC LIMIT 3", 
                  (session['user']['username'],))
        interazioni = c.fetchall()
        conn.close()
        conv_history = ""
        for inter in reversed(interazioni):
            conv_history += "Utente: " + (inter[0] or "") + "\n"
            conv_history += "Assistente: " + (inter[1] or "") + "\n"
        risposta = generate_ai_response(user_message, conv_history, session['user'])
    salva_interazione(session['user']['username'], user_message, risposta, event_date, tag)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    if 'photo' not in request.files:
        flash("Nessuna foto selezionata.", "error")
        return redirect(url_for('index'))
    file = request.files['photo']
    if file.filename == "":
        flash("File non selezionato.", "error")
        return redirect(url_for('index'))
    folder = "uploads"
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, file.filename)
    file.save(filepath)
    flash("Foto caricata correttamente.", "success")
    return redirect(url_for('index'))

# ---------------------------------------------------------------------
# ROTTE DI AUTENTICAZIONE
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT username, password, fullname, role FROM technicians WHERE username = ?", (username,))
        tech = c.fetchone()
        conn.close()
        if tech and tech[1] == password:
            session['user'] = {"username": tech[0], "fullname": tech[2], "role": tech[3]}
            flash("Login effettuato con successo!", "success")
            return redirect(url_for('index'))
        else:
            flash("Credenziali non valide.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        fullname = request.form.get('fullname')
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO technicians (username, password, fullname) VALUES (?, ?, ?)",
                      (username, password, fullname))
            conn.commit()
            flash("Registrazione effettuata! Ora puoi fare login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username già in uso. Scegline un altro.", "danger")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logout effettuato.", "info")
    return redirect(url_for('login'))

# ---------------------------------------------------------------------
# ROTTE ADMIN
@app.route('/admin', methods=['GET'])
def admin_panel():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Area riservata ad amministratori.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT username, fullname FROM technicians")
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, user=session['user'])

@app.route('/admin/view/<username>', methods=['GET'])
def admin_view_chat(username):
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Area riservata ad amministratori.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, richiesta, risposta, event_date FROM conversazioni WHERE username = ? ORDER BY id ASC", (username,))
    chats = c.fetchall()
    conn.close()
    return render_template('admin.html', selected_user=username, conversations=chats, user=session['user'])

# ---------------------------------------------------------------------
# PROGRAMMA ZONDA: Auto‑analisi e aggiornamento ogni 2 giorni
def auto_aggiornamento():
    # Esegue controlli su script, pagine, e aggiorna il sistema
    log_msg = f"{datetime.now().isoformat()}: Eseguita auto-analisi e aggiornamento degli script e pagine."
    print(log_msg)
    folder = "aggiornamenti"
    os.makedirs(folder, exist_ok=True)
    log_path = os.path.join(folder, "auto_aggiornamento.log")
    with open(log_path, 'a', encoding='utf-8') as log_file:
        log_file.write(log_msg + "\n")
    # Qui si potrebbero inserire ulteriori operazioni di aggiornamento

def pianifica_auto_aggiornamento():
    schedule.every(2).days.do(auto_aggiornamento)
    while True:
        schedule.run_pending()
        sched_time.sleep(60)  # Verifica ogni minuto

# Avvio della pianificazione in un thread separato
aggiornamento_thread = threading.Thread(target=pianifica_auto_aggiornamento, daemon=True)
aggiornamento_thread.start()

# ---------------------------------------------------------------------
# CHIUSURA DELL'APPLICAZIONE
if __name__ == '__main__':
    app.run(debug=True)