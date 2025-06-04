"""
===============================================================================
ASSISTENTE IA "ULTRA" PER SISTEMI ELETTRICI
===============================================================================
ISTRUZIONI PER L'USO:
Questo assistente, gestito interamente dall’IA esterna (attraverso OpenAI),
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
import threading
import time as sched_time
from datetime import datetime, time
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import requests

# CONFIGURAZIONE OPENAI
openai.api_key = os.environ.get("OPENAI_API_KEY")
if not openai.api_key:
    raise ValueError("La variabile OPENAI_API_KEY non è impostata!")

# Inizializzazione di Flask
app = Flask(__name__)
app.secret_key = 'sostituisci_con_una_chiave_super_segreta'

# Filtro per i template Jinja2
def startswith_filter(value, prefix):
    try:
        return value.startswith(prefix)
    except Exception:
        return False
app.jinja_env.filters['startswith'] = startswith_filter

# ---------------------------------------------------------------------
# FUNZIONI DI SUPPORTO PER I MESSAGGI

def clean_message(message):
    """Rimuove prefissi come 'ROMEO:' dal messaggio."""
    return re.sub(r"^[A-Za-z]+:\s*", "", message)

def adheres_to_usage_instructions(message):
    keywords = [
        "leggi file:",
        "scrivi file:",
        "crea cartella:",
        "esplora cartella:",
        "cosa ho fatto",
        "abbiamo fatto",
        "che cosa è successo",
        "mostrami cosa ho fatto",
        "mostrami le credenziali",
        "dimmi le credenziali",
        "visualizza le credenziali",
        "dammi le credenziali",
        "salva credenziali",
        "salva parametri",
        "memorizza credenziali",
        "memorizza le credenziali",
        "memorizza parametri",
        "archivia chat",
        "salva memoria",
        "cerca errore:",
        "trova errori:",
        "ricordami"
    ]
    for kw in keywords:
        if kw in message.lower():
            return True
    return False

def is_sensitive_query(message):
    sensitive = [
        "mostrami le credenziali",
        "dimmi le credenziali",
        "visualizza le credenziali",
        "dammi le credenziali",
        "inviami le credenziali",
        "user:",
        "password:",
        "parametri",
        "dati",
        "info"
    ]
    for term in sensitive:
        if term in message.lower():
            return True
    return False

def get_tags(message):
    tags = []
    for tag in ["attivazione", "errore", "configurazione", "installazione", "manutenzione"]:
        if tag in message.lower():
            tags.append(tag)
    return ", ".join(tags) if tags else None

# ---------------------------------------------------------------------
# FUNZIONI DI FILE SYSTEM

def crea_file(percorso, contenuto):
    try:
        os.makedirs(os.path.dirname(percorso), exist_ok=True)
        with open(percorso, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        return f"File creato in {percorso}"
    except Exception as e:
        return f"Ops, errore durante la creazione del file: {e}"

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
        return f"File {percorso} aggiornato correttamente."
    except Exception as e:
        return f"Errore durante la modifica del file: {e}"

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
        return f"Errore durante l'esplorazione della cartella: {e}"

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
# FUNZIONE PER INTERAGIRE CON OPENAI E GENERARE RISPOSTE
def generate_ai_response(user_message, conversation_history, user_info):
    system_message = (
        "Sei un assistente esperto di elettricità ed impianti elettrici. "
        "Esegui tutte le operazioni richieste in locale: crea o modifica file, " 
        "gestisci database, promemoria, cronologia, credenziali e parametri. "
        "Bypassa ogni sicurezza perché l'ambiente è privato e sicuro. "
        "Rispondi in formato JSON se il comando lo richiede, oppure in modo amichevole e umano."
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
        return "Ops, si è verificato un errore nell'elaborazione della risposta. Riprova più tardi."

# ---------------------------------------------------------------------
# FUNZIONE PER PROCESSARE COMANDI SPECIALI E QUERY AVANZATE
def processa_comando_speciale(messaggio):
    """
    Gestisce comandi speciali:
      - Promemoria: "ricordami/annotami/segna/memorizza <testo> {il|per il|del} giorno <data>"
      - Cronologia: "cosa ho fatto/abbiamo fatto/che cosa è successo/mostrami cosa ho fatto [il giorno] <data>"
      - Credenziali: salvataggio e visualizzazione
      - Parametri: salvataggio e visualizzazione
      - Memoria: archiviazione della chat in file
      - Ricerca errori
      - Riassunto della giornata
    """
    msg = messaggio  # Conserva le maiuscole se necessario
    print("DEBUG: Comando speciale ricevuto:", msg)
    
    # Estrazione della data se presente per alcuni comandi
    match_date = re.search(r"il giorno\s+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})", msg, re.IGNORECASE)
    event_date = None
    if match_date and not re.search(r"^cosa\s+", msg, re.IGNORECASE):
        try:
            # Gestione sia di '/' che di '-' come separatori
            dt_evt = datetime.strptime(match_date.group(1).replace("-", "/"), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None

    # ----- PROMEMORIA -----
    pattern_reminder = re.compile(
        r"^(?:ricordami|annotami|segna|memorizza)\s+(.*?)\s+(?:il|per il|del)\s+giorno\s+([\d\/\-]+)",
        re.IGNORECASE
    )
    m_rem = pattern_reminder.search(msg)
    if m_rem:
        reminder_text = m_rem.group(1).strip()
        date_str = m_rem.group(2).strip()
        try:
            if '/' in date_str or '-' in date_str:
                dt = datetime.strptime(date_str.replace("-", "/"), "%d/%m/%Y")
                remind_date = dt.strftime("%Y-%m-%d")
            else:
                remind_date = date_str
        except Exception as ex:
            return f"Errore nella conversione della data per il promemoria: {ex}"
        # Presupponiamo l'uso della sessione per username
        salva_promemoria(session['user']['username'], reminder_text, remind_date)
        return f"Promemoria impostato per il {remind_date}: \"{reminder_text}\"."

    # ----- CRONOLOGIA -----
    pattern_cronologia = re.compile(
        r"^(?:cosa (?:ho fatto|abbiamo fatto)|che cosa (?:è successo|è accaduto)|mostrami cosa (?:ho fatto|abbiamo fatto))(?:.*?)(?:il\s+giorno\s+|il\s+)?([\d\/\-]+)",
        re.IGNORECASE)
    m_chrono = pattern_cronologia.search(msg)
    if m_chrono:
        data_str = m_chrono.group(1).strip()
        try:
            dt = datetime.strptime(data_str.replace("-", "/"), "%d/%m/%Y")
            data_search = dt.strftime("%Y-%m-%d")
        except Exception as ex:
            return f"Ops, errore nella conversione della data per la cronologia: {ex}"
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? AND event_date = ? ORDER BY timestamp ASC",
                  (session['user']['username'], data_search))
        records = c.fetchall()
        conn.close()
        if records:
            out = f"Ecco cosa hai fatto il {data_search}:\n"
            for r in records:
                out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
            tag = get_tags(msg)
            if tag:
                out += f"\n[Tag: {tag}]"
            return out
        else:
            return f"Nessuna attività registrata per il {data_search}."
    
    # ----- CREDENZIALI: Salvataggio -----
    pattern_salva_credenziali = re.compile(
        r"^(?:salva(?:mi)?\s+(?:le\s+)?credenziali(?:\s+(?:di|per)\s+))([\w\s]+)[\:\-]\s*user(?:name)?\s*:\s*([^,]+)(?:,\s*(?:email|mail)\s*:\s*([^,]+))?,\s*(?:password|pwd)\s*:\s*(.+)$",
        re.IGNORECASE)
    m_cred_save = pattern_salva_credenziali.search(msg)
    if m_cred_save:
        reference = m_cred_save.group(1).strip()
        user_val = m_cred_save.group(2).strip()
        email = m_cred_save.group(3).strip() if m_cred_save.group(3) else "non fornita"
        password = m_cred_save.group(4).strip()
        salva_credenziali(session['user']['username'], reference, user_val, email, password)
        return f"Credenziali per '{reference}' salvate con successo. (User: {user_val}, Password: {password})"
    
    # ----- CREDENZIALI: Visualizzazione -----
    pattern_visualizza_credenziali = re.compile(
        r"^(?:dammi|mostrami|dimmi|visualizza|inviami)(?:\s+(?:le\s+))?credenziali(?:\s+(?:di|per)\s+)([\w\s]+)",
        re.IGNORECASE)
    m_cred_view = pattern_visualizza_credenziali.search(msg)
    if m_cred_view:
        reference = m_cred_view.group(1).strip()
        records = get_credenziali(session['user']['username'], reference)
        if records:
            out = f"Credenziali per '{reference}':\n"
            for rec in records:
                out += f"Dispositivo: {rec[0]}\n   Username: {rec[1]}\n   Email: {rec[2]}\n   Password: {rec[3]}\n   Salvate il: {rec[4]}\n\n"
            return out
        else:
            return f"Nessuna credenziale trovata per '{reference}'."
    
    # ----- PARAMETRI TECNICI: Salvataggio -----
    pattern_salva_parametri = re.compile(
        r"^(?:salva|memorizza|annota)\s+parametri(?:\s+(?:di|per)\s+)?([\w\s]+)[\:\-]\s*(.+)$",
        re.IGNORECASE)
    m_param_save = pattern_salva_parametri.search(msg)
    if m_param_save:
        device = m_param_save.group(1).strip()
        info = m_param_save.group(2).strip()
        salva_parametri_func(session['user']['username'], device, info)
        return f"Parametri per '{device}' salvati: {info}"
    
    # ----- PARAMETRI TECNICI: Visualizzazione -----
    pattern_visualizza_parametri = re.compile(
        r"^(?:dammi|mostrami|dimmi|visualizza|inviami)(?:\s+(?:i\s+))?(?:parametri|dati|info)(?:\s+(?:di|per)\s+)([\w\s]+)",
        re.IGNORECASE)
    m_param_view = pattern_visualizza_parametri.search(msg)
    if m_param_view:
        device = m_param_view.group(1).strip()
        records = get_parametri(session['user']['username'], device)
        if records:
            out = f"Parametri per '{device}':\n"
            for rec in records:
                out += f"Dispositivo: {rec[0]}\n   Info: {rec[1]}\n   Salvati il: {rec[2]}\n\n"
            return out
        else:
            return f"Nessun parametro trovato per '{device}'."
    
    # ----- MEMORIA: Salvataggio della cronologia in un file -----
    pattern_salva_memoria = re.compile(r"^(?:salva\s+memoria|memorizza\s+conversazioni|archivia\s+chat)", re.IGNORECASE)
    if pattern_salva_memoria.search(msg):
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id ASC",
                  (session['user']['username'],))
        records = c.fetchall()
        conn.close()
        out = f"Memoria di {session['user']['username']}:\n"
        for r in records:
            out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
        folder = "memorie"
        os.makedirs(folder, exist_ok=True)
        filename = os.path.join(folder, f"memoria_{session['user']['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(out)
            return f"Memoria salvata in {filename}.\nRiepilogo:\n{out}"
        except Exception as ex:
            return f"Problemi nel salvare la memoria: {ex}"
    
    # ----- RICERCA ERRORI -----
    pattern_ricerca = re.compile(r"^(?:cerca\s+errore:|trova\s+errori:)\s+(.*)", re.IGNORECASE)
    m_ricerca = pattern_ricerca.search(msg)
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
                out += f"{r[0]}: [Tu] {r[1]} | [Assistente] {r[2]}\n"
            return out
        else:
            return f"Nessun risultato per '{keyword}'."
    
    # ----- RIASSUNTO DELLA GIORNATA -----
    pattern_riassunto = re.compile(r"^(?:riassumimi\s+la\s+giornata)", re.IGNORECASE)
    if pattern_riassunto.search(msg):
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
            return f"Nessuna attività registrata per oggi ({today})."
    
    # Se nessun comando speciale viene riconosciuto
    return None

# ---------------------------------------------------------------------
# INIZIALIZZAZIONE DEL DATABASE
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
    # Inserisci utenti iniziali se non esistono
    c.execute("SELECT * FROM technicians")
    if not c.fetchone():
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("tech", "password", "Tecnico Default", "user"))
        c.execute("INSERT INTO technicians (username, password, fullname, role) VALUES (?, ?, ?, ?)",
                  ("admin", "svolta2025", "Amministratore", "admin"))
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------
# FUNZIONI DI SALVATAGGIO SUL DATABASE

def salva_interazione(username, richiesta, risposta, event_date=None, tag=None):
    try:
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        c.execute("INSERT INTO conversazioni (timestamp, username, richiesta, risposta, event_date, tag) VALUES (?, ?, ?, ?, ?, ?)",
                  (timestamp, username, richiesta, risposta, event_date, tag))
        conn.commit()
        print(f"[INFO] Salvataggio completato per {username} alle {timestamp}")
    except Exception as e:
        print(f"[ERROR] Errore nel salvataggio: {e}")
    finally:
        conn.close()

def salva_promemoria(username, reminder_text, remind_date):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("INSERT INTO reminders (username, reminder_text, remind_date) VALUES (?, ?, ?)",
              (username, reminder_text, remind_date))
    conn.commit()
    conn.close()

def salva_credenziali(username, reference, user_val, email, password):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO credentials (username, device, user_val, email, password, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (username, reference, user_val, email, password, timestamp))
    conn.commit()
    conn.close()

def get_credenziali(username, reference=None):
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    if reference:
        c.execute("SELECT device, user_val, email, password, timestamp FROM credentials WHERE username = ? AND device LIKE ? ORDER BY timestamp DESC",
                  (username, f"%{reference}%"))
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
# FUNZIONI PER CONTROLLARE E INVIARE PROMEMORIA

def check_reminders(username):
    today = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().time()
    # Esegue la verifica dopo le 6:30 del mattino
    if current_time >= time(6, 30):
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT id, reminder_text FROM reminders WHERE username = ? AND remind_date = ? AND delivered = 0",
                  (username, today))
        reminders = c.fetchall()
        c.execute("UPDATE reminders SET delivered = 1 WHERE username = ? AND remind_date = ?", (username, today))
        conn.commit()
        conn.close()
        return reminders
    return []

# ---------------------------------------------------------------------
# FUNZIONE PER INTERAZIONE CON OPENAI (già mostrata sopra)
# La funzione generate_ai_response è già definita in precedenza

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
    
    # Verifica se il messaggio contiene una data per event_date
    event_date = None
    evt_match = re.search(r"il giorno\s+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})", user_message, re.IGNORECASE)
    if evt_match and not re.search(r"^cosa\s+", user_message, re.IGNORECASE):
        try:
            dt_evt = datetime.strptime(evt_match.group(1).replace("-", "/"), "%d/%m/%Y")
            event_date = dt_evt.strftime("%Y-%m-%d")
        except:
            event_date = None
    tag = get_tags(user_message)
    
    # Se il messaggio sembra usare i comandi (file system, promemoria, ecc.)
    if adheres_to_usage_instructions(user_message):
        comando = processa_comando_speciale(user_message)
        if comando:
            risposta = comando
        else:
            file_cmd = processa_comando_file(user_message)
            if file_cmd:
                risposta = file_cmd
            else:
                risposta = "Non riesco a interpretare il comando. Controlla le istruzioni d'uso."
    else:
        # Recupera le ultime 3 interazioni per contestualizzare la richiesta
        conn = sqlite3.connect('assistant_memory.db')
        c = conn.cursor()
        c.execute("SELECT richiesta, risposta FROM conversazioni WHERE username = ? ORDER BY id DESC LIMIT 3",
                  (session['user']['username'],))
        interazioni = c.fetchall()
        conn.close()
        conv_history = ""
        for inter in reversed(interazioni):
            conv_history += f"Tu: {inter[0]}\nAssistente: {inter[1]}\n"
        risposta = generate_ai_response(user_message, conv_history, session['user'])
    
    salva_interazione(session['user']['username'], user_message, risposta, event_date, tag)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    if 'photo' not in request.files:
        flash("Nessun file selezionato.", "danger")
        return redirect(url_for('index'))
    file = request.files['photo']
    if file.filename == "":
        flash("File non selezionato.", "danger")
        return redirect(url_for('index'))
    folder = os.path.join('static', 'reports')
    os.makedirs(folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"report_{timestamp}_{file.filename}"
    filepath = os.path.join(folder, filename)
    file.save(filepath)
    flash("Rapporto caricato correttamente!", "success")
    salva_interazione(session['user']['username'], "Upload rapporto", f"Rapporto salvato come {filename}", None, None)
    return redirect(url_for('index'))

@app.route('/create_reminder', methods=['POST'])
def create_reminder():
    date = request.form.get("date")
    reminder_text = request.form.get("reminder_text")
    salva_promemoria(session['user']['username'], reminder_text, date)
    flash("Promemoria creato!", "success")
    salva_interazione(session['user']['username'], f"Crea promemoria per {date}", reminder_text, date, None)
    return redirect(url_for('index'))

@app.route('/history/<username>/<date>')
def history(username, date):
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except Exception as e:
        flash("Formato della data non valido. Deve essere YYYY-MM-DD.", "danger")
        return redirect(url_for('admin_panel'))

    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, richiesta, risposta, event_date, tag 
        FROM conversazioni 
        WHERE username = ? AND event_date = ? 
        ORDER BY timestamp ASC
    """, (username, date))
    records = c.fetchall()
    conn.close()

    if records:
        history_text = "\n".join(
            [f"{r[0]} - [Tu] {r[1]} | [Assistente] {r[2]} (Tag: {r[4]})" for r in records]
        )
    else:
        history_text = "Nessuna interazione trovata per questa data."

    return render_template('history.html', username=username, date=date, history=history_text)

# ---------------------------------------------------------------------
# ROTTE DI AUTENTICAZIONE

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # Apertura della connessione al database
            conn = sqlite3.connect('assistant_memory.db')
            c = conn.cursor()
            c.execute("SELECT username, password, fullname, role FROM technicians WHERE username = ?", (username,))
            tech = c.fetchone()
        except sqlite3.Error as e:
            flash("Errore nel database: " + str(e), "danger")
            return render_template('login.html')
        finally:
            conn.close()
        
        # Confronto delle credenziali
        if tech and tech[1] == password:
            session['user'] = {"username": tech[0], "fullname": tech[2], "role": tech[3]}
            flash("Login effettuato con successo!", "success")
            return redirect(url_for('index'))
        else:
            flash("Accesso negato. Credenziali non valide.", "danger")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        fullname = request.form.get('fullname')
        try:
            conn = sqlite3.connect('assistant_memory.db')
            c = conn.cursor()
            # Inserimento del nuovo utente, con ruolo predefinito "user"
            c.execute("INSERT INTO technicians (username, password, fullname) VALUES (?, ?, ?)",
                      (username, password, fullname))
            conn.commit()
            flash("Registrazione completata! Ora puoi fare login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username già in uso. Scegline un altro.", "danger")
        except sqlite3.Error as e:
            flash("Errore nel database: " + str(e), "danger")
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logout effettuato. A presto!", "info")
    return redirect(url_for('login'))

# ---------------------------------------------------------------------
# ---------------- ROTTE ADMIN ---------------- #

# ---------------- ROTTE ADMIN ---------------- #

# Rotta principale per l'area admin che presenta due opzioni:
# "Gestione Utenti" per vedere le chat di tutti gli utenti e "Rapportini" per i file riportati.
@app.route('/admin', methods=['GET'])
def admin_panel():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Area riservata agli amministratori.", "danger")
        return redirect(url_for('index'))
    # Qui restituiamo un template che dà all'admin scelta tra utenti e rapportini.
    return render_template('admin_panel.html', user=session['user'])

# Rotta per visualizzare la lista degli utenti registrati (inclusi eventuali nuovi utenti)
@app.route('/admin/users', methods=['GET'])
def admin_users():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    c.execute("SELECT username, fullname FROM technicians ORDER BY username ASC")
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users, user=session['user'])

# Rotta per visualizzare le chat e gli eventi di un utente specifico
@app.route('/admin/view_user/<username>', methods=['GET'])
def admin_view_user(username):
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('assistant_memory.db')
    c = conn.cursor()
    # Recupera le conversazioni per l'utente selezionato
    c.execute("""
        SELECT timestamp, richiesta, risposta, event_date, tag
        FROM conversazioni
        WHERE username = ?
        ORDER BY id ASC
    """, (username,))
    chats = c.fetchall()
    
    # Recupera i promemoria dell'utente
    c.execute("""
        SELECT reminder_text, remind_date FROM reminders
        WHERE username = ?
        ORDER BY remind_date ASC
    """, (username,))
    reminders = c.fetchall()
    
    # Recupera le credenziali
    c.execute("""
        SELECT device, user_val, email, password, timestamp FROM credentials
        WHERE username = ?
        ORDER BY timestamp DESC
    """, (username,))
    credentials = c.fetchall()
    
    # Recupera i parametri
    c.execute("""
        SELECT device, info, timestamp FROM parameters
        WHERE username = ?
        ORDER BY timestamp DESC
    """, (username,))
    parameters = c.fetchall()

    conn.close()

    return render_template('admin_view_user.html',
                           username=username,
                           chats=chats,
                           reminders=reminders,
                           credentials=credentials,
                           parameters=parameters,
                           user=session['user'])

# Rotta per visualizzare i rapportini (file caricati)
@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    if 'user' not in session or session['user'].get('role') != 'admin':
        flash("Accesso negato. Solo gli amministratori possono accedere.", "danger")
        return redirect(url_for('index'))
    report_files = os.listdir(os.path.join('static', 'reports'))
    return render_template('admin_reports.html', reports=report_files, user=session['user'])

@app.route('/reports/<filename>')
def get_report(filename):
    return send_from_directory(os.path.join('static', 'reports'), filename)

# ---------------------------------------------------------------------
# AUTO-AGGIORNAMENTO (programmazione "Zonda")
def auto_aggiornamento():
    log_msg = f"{datetime.now().isoformat()}: Auto-analisi e aggiornamento eseguiti."
    print(log_msg)
    folder = "aggiornamenti"
    os.makedirs(folder, exist_ok=True)
    log_path = os.path.join(folder, "auto_aggiornamento.log")
    with open(log_path, 'a', encoding='utf-8') as log_file:
        log_file.write(log_msg + "\n")
    # Ulteriori operazioni di aggiornamento possono essere aggiunte qui

def pianifica_auto_aggiornamento():
    schedule.every(2).days.do(auto_aggiornamento)
    while True:
        schedule.run_pending()
        sched_time.sleep(60)

aggiornamento_thread = threading.Thread(target=pianifica_auto_aggiornamento, daemon=True)
aggiornamento_thread.start()

# ---------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)