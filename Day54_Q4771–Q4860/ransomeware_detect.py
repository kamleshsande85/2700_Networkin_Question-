import configparser
import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.ensemble import IsolationForest
import psutil
import subprocess
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='ransomware_detector.log'
)
logger = logging.getLogger('RansomwareDetector')

# Get script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self, behavioral_text):
        self.behavioral_text = behavioral_text
        
    def on_modified(self, event):
        if not event.is_directory:
            self.log(f'File modified: {event.src_path}')
            
    def on_created(self, event):
        if not event.is_directory:
            self.log(f'File created: {event.src_path}')
            
    def on_deleted(self, event):
        if not event.is_directory:
            self.log(f'File deleted: {event.src_path}')
            
    def log(self, message):
        self.behavioral_text.insert(tk.END, f"{time.ctime()}: {message}\n")
        self.behavioral_text.see(tk.END)
        self.behavioral_text.tag_add('behavioral', 'end-1c linestart', 'end-1c lineend')
        logger.info(message)

class RansomwareStyledGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.load_config()
        self.setup_anomaly_model()
        self.create_widgets()
        self.setup_styles()
        
    def setup_window(self):
        self.root.title("Advanced Ransomware Detection System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg='#1e1e1e')
        self.running = False
        self.observer = None
        
        # Make the window resizable
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def load_config(self):
        self.config = configparser.ConfigParser()
        config_path = os.path.join(SCRIPT_DIR, "config.ini")
        
        if not os.path.exists(config_path):
            self.create_default_config(config_path)
            
        self.config.read(config_path)
        
        # Set paths with fallbacks
        self.target_dir = os.path.abspath(os.path.expanduser(
            self.config.get('Settings', 'target_dir', fallback=os.path.join(SCRIPT_DIR, 'test_files'))
        ))
        self.yara_rule = os.path.abspath(os.path.expanduser(
            self.config.get('Settings', 'yara_rule', fallback=os.path.join(SCRIPT_DIR, 'ransomware_rule.yar'))
        ))
        self.cpu_threshold = float(self.config.get('Settings', 'cpu_threshold', fallback=80))
        self.anomaly_contamination = float(self.config.get('Settings', 'anomaly_contamination', fallback=0.2))
        
        # Create directories if needed
        os.makedirs(self.target_dir, exist_ok=True)
        
    def create_default_config(self, config_path):
        """Create default config file if not exists"""
        self.config['Settings'] = {
            'target_dir': './test_files',
            'yara_rule': './ransomware_rule.yar',
            'cpu_threshold': '80',
            'anomaly_contamination': '0.2'
        }
        with open(config_path, 'w') as f:
            self.config.write(f)
        logger.info(f"Created default config file at {config_path}")
        
    def setup_anomaly_model(self):
        self.model_data = [[5, 0.1], [10, 0.2], [8, 0.15], [100, 0.9], [90, 0.8]]
        self.model = IsolationForest(contamination=self.anomaly_contamination, random_state=42)
        self.model.fit(self.model_data)
        
    def setup_styles(self):
        # Custom font
        self.custom_font = font.Font(family='Helvetica', size=10)
        self.title_font = font.Font(family='Helvetica', size=14, weight='bold')
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('.', background='#1e1e1e', foreground='white')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='white', font=self.custom_font)
        self.style.configure('TButton', 
                           background='#2d2d2d', 
                           foreground='white',
                           borderwidth=1,
                           relief='raised',
                           font=self.custom_font)
        self.style.map('TButton',
                      background=[('active', '#3e3e3e'), ('disabled', '#1a1a1a')],
                      foreground=[('disabled', '#555555')])
        
        # Configure notebook style
        self.style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                            background='#2d2d2d', 
                            foreground='white',
                            padding=[10, 5],
                            font=self.custom_font)
        self.style.map('TNotebook.Tab',
                     background=[('selected', '#0078d7'), ('active', '#3e3e3e')],
                     foreground=[('selected', 'white')])
        
    def create_widgets(self):
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_columnconfigure(0, weight=1)
        
        # Header
        header_frame = ttk.Frame(main_container)
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        
        ttk.Label(
            header_frame, 
            text="Advanced Ransomware Detection System", 
            font=self.title_font,
            foreground='#0078d7'
        ).pack(side='left')
        
        # Button frame
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side='right')
        
        self.start_button = ttk.Button(
            button_frame, 
            text="Start Monitoring", 
            command=self.start_monitoring,
            style='TButton'
        )
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="Stop Monitoring", 
            command=self.stop_monitoring,
            state='disabled',
            style='TButton'
        )
        self.stop_button.pack(side='left', padx=5)
        
        # Notebook for alerts
        self.notebook = ttk.Notebook(main_container)
        self.notebook.grid(row=1, column=0, sticky='nsew')
        
        # Behavioral tab
        behavioral_frame = ttk.Frame(self.notebook)
        self.notebook.add(behavioral_frame, text='Behavioral Monitoring')
        behavioral_frame.grid_rowconfigure(0, weight=1)
        behavioral_frame.grid_columnconfigure(0, weight=1)
        
        self.behavioral_text = scrolledtext.ScrolledText(
            behavioral_frame,
            wrap=tk.WORD,
            bg='#252526',
            fg='white',
            insertbackground='white',
            font=self.custom_font,
            padx=10,
            pady=10
        )
        self.behavioral_text.grid(row=0, column=0, sticky='nsew')
        self.behavioral_text.tag_configure('behavioral', foreground='#569cd6')
        
        # Anomaly tab
        anomaly_frame = ttk.Frame(self.notebook)
        self.notebook.add(anomaly_frame, text='Anomaly Detection')
        anomaly_frame.grid_rowconfigure(0, weight=1)
        anomaly_frame.grid_columnconfigure(0, weight=1)
        
        self.anomaly_text = scrolledtext.ScrolledText(
            anomaly_frame,
            wrap=tk.WORD,
            bg='#252526',
            fg='white',
            insertbackground='white',
            font=self.custom_font,
            padx=10,
            pady=10
        )
        self.anomaly_text.grid(row=0, column=0, sticky='nsew')
        self.anomaly_text.tag_configure('anomaly', foreground='#d69d85')
        
        # Signature tab
        signature_frame = ttk.Frame(self.notebook)
        self.notebook.add(signature_frame, text='Signature Detection')
        signature_frame.grid_rowconfigure(0, weight=1)
        signature_frame.grid_columnconfigure(0, weight=1)
        
        self.signature_text = scrolledtext.ScrolledText(
            signature_frame,
            wrap=tk.WORD,
            bg='#252526',
            fg='white',
            insertbackground='white',
            font=self.custom_font,
            padx=10,
            pady=10
        )
        self.signature_text.grid(row=0, column=0, sticky='nsew')
        self.signature_text.tag_configure('signature', foreground='#608b4e')
        
        # Status bar
        self.status_var = tk.StringVar(value="Status: Idle")
        status_bar = ttk.Label(
            main_container,
            textvariable=self.status_var,
            relief='sunken',
            anchor='w',
            padding=5,
            style='TLabel'
        )
        status_bar.grid(row=2, column=0, sticky='ew', pady=(10, 0))
        
        # Tooltips
        self.create_tooltip(self.start_button, "Start monitoring the target directory for ransomware activity")
        self.create_tooltip(self.stop_button, "Stop monitoring the target directory")
        
    def create_tooltip(self, widget, text):
        def enter(event):
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 20}+{event.y_root + 20}")
            label = tk.Label(
                tooltip, 
                text=text, 
                bg='#ffffe0', 
                fg='#000000', 
                relief='solid', 
                borderwidth=1, 
                font=('Arial', 8)
            )
            label.pack()
            widget.tooltip = tooltip
            
        def leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
        
    def log(self, text_area, message, tag=None):
        text_area.insert(tk.END, f"{time.ctime()}: {message}\n")
        if tag:
            text_area.tag_add(tag, 'end-1c linestart', 'end-1c lineend')
        text_area.see(tk.END)
        logger.info(message)
        
    def start_monitoring(self):
        if not self.running:
            self.running = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.status_var.set(f"Status: Monitoring {self.target_dir}")
            self.log(self.behavioral_text, "Starting monitoring...", 'behavioral')
            
            # Start file system observer
            self.observer = Observer()
            event_handler = RansomwareDetector(self.behavioral_text)
            self.observer.schedule(event_handler, self.target_dir, recursive=False)
            self.observer.start()
            
            # Start monitoring thread
            Thread(target=self.monitor_loop, daemon=True).start()
            
    def stop_monitoring(self):
        if self.running:
            self.running = False
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.status_var.set("Status: Idle")
            self.log(self.behavioral_text, "Monitoring stopped.", 'behavioral')
            
            if self.observer:
                self.observer.stop()
                self.observer.join()
                
    def monitor_loop(self):
        while self.running:
            try:
                # Behavioral: CPU usage
                cpu = psutil.cpu_percent(interval=1)
                if cpu > self.cpu_threshold:
                    self.log(self.behavioral_text, f"High CPU usage detected: {cpu}%", 'behavioral')
                    
                # Anomaly: File count and CPU
                file_count = len(os.listdir(self.target_dir))
                test = [[file_count, cpu / 100]]
                if self.model.predict(test)[0] == -1:
                    self.log(self.anomaly_text, f"Possible ransomware: File count={file_count}, CPU={cpu}%", 'anomaly')
                    
                # Signature: YARA scan
                for filename in os.listdir(self.target_dir):
                    filepath = os.path.join(self.target_dir, filename)
                    if os.path.isfile(filepath):
                        try:
                            result = subprocess.run(
                                ['yara', self.yara_rule, filepath], 
                                capture_output=True, 
                                text=True
                            )
                            if result.stdout:
                                self.log(self.signature_text, f"Ransomware detected in {filepath}", 'signature')
                        except (subprocess.CalledProcessError, FileNotFoundError) as e:
                            self.log(self.signature_text, f"YARA scan error: {str(e)}", 'signature')
                            
                time.sleep(1)
            except Exception as e:
                self.log(self.behavioral_text, f"Monitoring error: {str(e)}", 'behavioral')

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = RansomwareStyledGUI(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"Application failed: {str(e)}")
        messagebox.showerror("Error", f"Application failed: {str(e)}")