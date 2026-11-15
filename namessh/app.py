"""Tkinter GUI and interactive SSH terminal."""
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import pyte
from .core import connect_ssh, local_networks, scan_network

BG = '#0c1220'
PANEL = '#151e2e'
TEXT = '#e9f1ff'
MUTED = '#92a2ba'
ACCENT = '#4bd5b4'


class App:
    def __init__(self, root):
        self.root = root
        root.title('NameSSH — локальный SSH-клиент')
        root.geometry('1150x750')
        root.minsize(850, 600)
        root.configure(bg=BG)
        self.events = queue.Queue()
        self.cancel_scan = threading.Event()
        self.session_stop = threading.Event()
        self.outgoing = queue.Queue()
        self.connected = False
        self.connecting = False
        self.closed = False
        self.scan_active = False
        self.client = None
        self.channel = None
        self.screen = pyte.Screen(120, 32)
        self.stream = pyte.Stream(self.screen)
        self._style()
        self._build()
        self.refresh_networks()
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(50, self.process_events)

    def _style(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('TFrame', background=BG)
        s.configure('Panel.TFrame', background=PANEL)
        s.configure('TLabel', background=BG, foreground=TEXT, font=('Segoe UI', 10))
        s.configure('Muted.TLabel', background=BG, foreground=MUTED)
        s.configure('Panel.TLabel', background=PANEL, foreground=TEXT)
        s.configure('Title.TLabel', background=BG, foreground=TEXT, font=('Segoe UI', 20, 'bold'))
        s.configure('TButton', font=('Segoe UI', 10), padding=(12, 7), background='#27364d', foreground=TEXT, borderwidth=0)
        s.map('TButton', background=[('active', '#39516c'), ('disabled', '#202b3a')], foreground=[('disabled', '#738096')])
        s.configure('Accent.TButton', background=ACCENT, foreground='#09231f')
        s.map('Accent.TButton', background=[('active', '#7be5cb'), ('disabled', '#315851')], foreground=[('disabled', '#99bcb4')])
        s.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=29, borderwidth=0)
        s.configure('Treeview.Heading', background='#243247', foreground=TEXT, padding=7)
        s.map('Treeview', background=[('selected', '#285b59')])
        s.configure('TEntry', fieldbackground='#202d40', foreground=TEXT, insertcolor=TEXT, padding=5)
        s.configure('TCombobox', fieldbackground='#202d40', foreground=TEXT, padding=4)
        s.configure('Horizontal.TProgressbar', background=ACCENT, troughcolor='#263349')

    def _build(self):
        main = ttk.Frame(self.root, padding=22)
        main.pack(fill='both', expand=True)
        header = ttk.Frame(main); header.pack(fill='x')
        ttk.Label(header, text='NameSSH', style='Title.TLabel').pack(side='left')
        ttk.Label(header, text='  /  ваш доступ к устройствам в сети', style='Muted.TLabel').pack(side='left', padx=8)
        self.status = tk.StringVar(value='Не подключено')
        ttk.Label(header, textvariable=self.status, style='Muted.TLabel').pack(side='right')
        ttk.Label(main, text='Найдите SSH-устройства в локальной сети или подключитесь вручную.', style='Muted.TLabel').pack(anchor='w', pady=(4, 18))

        body = ttk.Frame(main); body.pack(fill='both', expand=True)
        left = ttk.Frame(body, width=340); left.pack(side='left', fill='y', padx=(0, 18)); left.pack_propagate(False)
        right = ttk.Frame(body); right.pack(side='left', fill='both', expand=True)
        ttk.Label(left, text='01  ПОИСК В СЕТИ', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 8))
        self.network = tk.StringVar()
        self.net_combo = ttk.Combobox(left, textvariable=self.network, state='readonly')
        self.net_combo.pack(fill='x')
        actions = ttk.Frame(left); actions.pack(fill='x', pady=8)
        self.scan_button = ttk.Button(actions, text='Найти устройства', style='Accent.TButton', command=self.start_scan)
        self.scan_button.pack(side='left', fill='x', expand=True)
        ttk.Button(actions, text='↻', width=3, command=self.refresh_networks).pack(side='left', padx=(6, 0))
        self.progress = ttk.Progressbar(left, maximum=100); self.progress.pack(fill='x', pady=(0, 8))
        self.scan_status = tk.StringVar(value='Выберите сеть и начните поиск')
        ttk.Label(left, textvariable=self.scan_status, style='Muted.TLabel', wraplength=330).pack(anchor='w', pady=(0, 8))
        self.devices = ttk.Treeview(left, columns=('ip', 'banner'), show='headings', height=8)
        self.devices.heading('ip', text='IP-адрес'); self.devices.heading('banner', text='SSH-сервер')
        self.devices.column('ip', width=120, stretch=False); self.devices.column('banner', width=180)
        self.devices.pack(fill='both', expand=True)
        self.devices.bind('<<TreeviewSelect>>', self.select_device)
        ttk.Label(left, text='Результаты — серверы SSH, не определение модели устройства.', style='Muted.TLabel', wraplength=330).pack(anchor='w', pady=(8, 0))

        ttk.Label(right, text='02  ПОДКЛЮЧЕНИЕ', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 8))
        form = ttk.Frame(right, style='Panel.TFrame', padding=14); form.pack(fill='x')
        for i in (0, 1, 2): form.columnconfigure(i, weight=1)
        self.host = tk.StringVar(); self.port = tk.StringVar(value='22'); self.username = tk.StringVar()
        self.password = tk.StringVar(); self.key_file = tk.StringVar()
        fields = [('IP или имя хоста', self.host, 0, 0, False), ('Порт', self.port, 0, 1, False),
                  ('Пользователь', self.username, 0, 2, False), ('Пароль / пароль ключа', self.password, 2, 0, True),
                  ('Файл приватного ключа (необязательно)', self.key_file, 2, 1, False)]
        for label, variable, row, col, secret in fields:
            ttk.Label(form, text=label, style='Panel.TLabel').grid(row=row, column=col, sticky='w', padx=4, pady=(0, 4))
            entry = ttk.Entry(form, textvariable=variable, show='•' if secret else '')
            entry.grid(row=row+1, column=col, sticky='ew', padx=4, pady=(0, 10))
        ttk.Button(form, text='Выбрать ключ', command=self.choose_key).grid(row=3, column=2, sticky='ew', padx=4, pady=(0, 10))
        buttons = ttk.Frame(form, style='Panel.TFrame'); buttons.grid(row=4, column=0, columnspan=3, sticky='ew', padx=4)
        self.connect_button = ttk.Button(buttons, text='Подключиться  →', style='Accent.TButton', command=self.start_connect)
        self.connect_button.pack(side='left')
        self.disconnect_button = ttk.Button(buttons, text='Отключиться', command=self.disconnect, state='disabled')
        self.disconnect_button.pack(side='left', padx=8)
        ttk.Label(right, text='03  ТЕРМИНАЛ', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(18, 8))
        self.terminal = tk.Text(right, bg='#080e19', fg='#cde6df', insertbackground=ACCENT,
                                font=('Consolas', 10), wrap='none', relief='flat', padx=12, pady=12,
                                undo=False, highlightthickness=1, highlightbackground='#26364a')
        self.terminal.pack(fill='both', expand=True)
        self.terminal.insert('1.0', 'Подключитесь к устройству, чтобы открыть терминал.\n')
        self.terminal.bind('<KeyPress>', self.keypress)
        self.terminal.bind('<<Paste>>', self.paste)
        ttk.Label(right, text='Кликните в терминал для ввода · Ctrl+Shift+V — вставить', style='Muted.TLabel').pack(anchor='w', pady=(6, 0))

    def refresh_networks(self):
        self.networks = local_networks()
        choices = [f'{n}  ·  {ip}  ·  {net}' + (' (только /24)' if limited else '') for n, ip, net, limited in self.networks]
        self.net_combo['values'] = choices
        if choices:
            self.net_combo.current(0)
        else:
            self.network.set(''); self.scan_status.set('Сеть IPv4 не найдена. Можно подключиться вручную.')

    def start_scan(self):
        index = self.net_combo.current()
        if index < 0 or self.scan_active:
            return
        try:
            port = self.get_port()
        except ValueError as e:
            messagebox.showerror('Порт', str(e)); return
        self.devices.delete(*self.devices.get_children())
        self.cancel_scan.clear(); self.scan_active = True
        self.scan_button.configure(state='disabled'); self.progress['value'] = 0
        network = self.networks[index][2]
        self.scan_status.set(f'Поиск SSH в {network}…')
        def run():
            try:
                scan_network(network, port, self.cancel_scan,
                             lambda done, total: self.events.put(('progress', done, total)),
                             lambda ip, banner: self.events.put(('found', ip, banner)))
                self.events.put(('scan_done', None))
            except Exception as exc:
                self.events.put(('scan_done', str(exc)))
        threading.Thread(target=run, daemon=True).start()

    def select_device(self, _event):
        selected = self.devices.selection()
        if selected:
            self.host.set(self.devices.item(selected[0], 'values')[0])

    def choose_key(self):
        path = filedialog.askopenfilename(title='Выберите приватный SSH-ключ')
        if path: self.key_file.set(path)

    def get_port(self):
        try: port = int(self.port.get())
        except ValueError: raise ValueError('Введите порт от 1 до 65535')
        if not 1 <= port <= 65535: raise ValueError('Введите порт от 1 до 65535')
        return port

    def start_connect(self):
        if self.connecting or self.connected: return
        host, user = self.host.get().strip(), self.username.get().strip()
        try: port = self.get_port()
        except ValueError as e: messagebox.showerror('Порт', str(e)); return
        if not host or not user:
            messagebox.showerror('Подключение', 'Укажите адрес и имя пользователя.'); return
        password, key = self.password.get(), self.key_file.get().strip()
        self.connecting = True; self.connect_button.configure(state='disabled')
        self.status.set(f'Подключение к {host}…')
        self.session_stop = threading.Event()
        self.outgoing = queue.Queue()
        stop, outgoing = self.session_stop, self.outgoing
        def confirm(hostname, algorithm, fp):
            answer = {'accepted': False}; event = threading.Event()
            self.events.put(('host_key', hostname, algorithm, fp, answer, event))
            while not event.wait(0.2):
                if stop.is_set(): return False
            return answer['accepted']
        def run():
            client = channel = None
            try:
                client = connect_ssh(host, port, user, password, key, confirm)
                if stop.is_set(): return
                channel = client.invoke_shell(term='xterm', width=120, height=32)
                channel.settimeout(0.1)
                self.events.put(('connected',))
                while not stop.is_set() and not channel.closed:
                    try:
                        while True:
                            data = outgoing.get_nowait()
                            channel.sendall(data)
                    except queue.Empty: pass
                    try:
                        data = channel.recv(32768)
                        if not data: break
                        self.events.put(('data', data))
                    except TimeoutError: pass
                self.events.put(('disconnected', None))
            except Exception as exc:
                self.events.put(('disconnected', str(exc)))
            finally:
                if channel: channel.close()
                if client: client.close()
        threading.Thread(target=run, daemon=True).start()

    def disconnect(self):
        self.session_stop.set()
        self.status.set('Отключение…')
        self.disconnect_button.configure(state='disabled')

    def keypress(self, event):
        if not self.connected: return 'break'
        if event.state & 0x4 and event.state & 0x1 and event.keysym.lower() == 'v':
            return self.paste(event)
        keys = {'Return': '\r', 'BackSpace': '\x7f', 'Tab': '\t', 'Escape': '\x1b',
                'Up': '\x1b[A', 'Down': '\x1b[B', 'Right': '\x1b[C', 'Left': '\x1b[D',
                'Home': '\x1b[H', 'End': '\x1b[F', 'Delete': '\x1b[3~',
                'Prior': '\x1b[5~', 'Next': '\x1b[6~'}
        data = keys.get(event.keysym, event.char)
        if event.state & 0x4 and event.keysym.lower() in 'abcdefghijklmnopqrstuvwxyz' and len(event.keysym) == 1:
            data = chr(ord(event.keysym.lower()) - ord('a') + 1)
        if data: self.outgoing.put(data.encode('utf-8'))
        return 'break'

    def paste(self, _event=None):
        if self.connected:
            try: self.outgoing.put(self.root.clipboard_get().encode('utf-8'))
            except tk.TclError: pass
        return 'break'

    def process_events(self):
        import codecs
        if not hasattr(self, 'decoder'): self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        try:
            while True:
                item = self.events.get_nowait(); kind = item[0]
                if kind == 'progress':
                    self.progress['value'] = item[1] * 100 / max(item[2], 1)
                    self.scan_status.set(f'Проверено: {item[1]} / {item[2]}')
                elif kind == 'found': self.devices.insert('', 'end', values=(item[1], item[2]))
                elif kind == 'scan_done':
                    self.scan_active = False; self.scan_button.configure(state='normal')
                    self.scan_status.set('Ошибка: ' + item[1] if item[1] else f'Готово. Найдено: {len(self.devices.get_children())}')
                elif kind == 'host_key':
                    _, hostname, algorithm, fp, answer, event = item
                    answer['accepted'] = messagebox.askyesno('Новый ключ сервера', f'Сервер: {hostname}\nТип: {algorithm}\nОтпечаток: {fp}\n\nСверьте отпечаток с устройством по доверенному каналу. Доверять этому ключу?')
                    event.set()
                elif kind == 'connected':
                    self.connected = True; self.connecting = False
                    self.disconnect_button.configure(state='normal'); self.status.set('Подключено')
                    self.screen.reset(); self.decoder.reset(); self.terminal.focus_set()
                elif kind == 'data':
                    self.stream.feed(self.decoder.decode(item[1]))
                    self.render_terminal()
                elif kind == 'disconnected':
                    self.connected = self.connecting = False
                    self.connect_button.configure(state='normal'); self.disconnect_button.configure(state='disabled')
                    self.status.set('Не подключено'); self.password.set('')
                    if item[1] and not self.session_stop.is_set(): messagebox.showerror('SSH', item[1])
        except queue.Empty: pass
        if not self.closed: self.root.after(50, self.process_events)

    def render_terminal(self):
        self.terminal.delete('1.0', 'end')
        self.terminal.insert('1.0', '\n'.join(self.screen.display))
        cursor = self.screen.cursor
        self.terminal.mark_set('insert', f'{cursor.y+1}.{cursor.x}')
        self.terminal.see('insert')

    def close(self):
        self.closed = True; self.cancel_scan.set(); self.session_stop.set(); self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()
