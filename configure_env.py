#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import string
import subprocess
import platform

class EnvConfiguratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Configuration Nextcloud Docker")
        self.root.geometry("700x650")
        
        # Variables pour stocker les valeurs
        self.nextcloud_host = tk.StringVar(value="nextcloud.example.com")
        self.traefik_dashboard_host = tk.StringVar(value="traefik.example.com")
        self.traefik_dashboard_port = tk.StringVar(value="8080")
        self.traefik_acme_email = tk.StringVar(value="your-email@example.com")
        self.traefik_log_level = tk.StringVar(value="INFO")
        self.mysql_root_password = tk.StringVar(value=self.generate_password())
        self.mysql_password = tk.StringVar(value=self.generate_password())
        self.mysql_database = tk.StringVar(value="nextcloud")
        self.mysql_user = tk.StringVar(value="nextcloud")
        self.traefik_dashboard_auth = tk.StringVar()
        self.traefik_dashboard_auth_user = tk.StringVar(value="admin")
        self.traefik_dashboard_auth_password = tk.StringVar(value=self.generate_password(12))
        self.timezone = tk.StringVar(value="Europe/Paris")
        
        # Création de l'interface
        self.create_widgets()
        
        # Charger les valeurs existantes si le fichier .env existe
        if os.path.exists(".env"):
            self.load_env_file()
    
    def create_widgets(self):
        # Style
        style = ttk.Style()
        style.configure("TLabel", padding=5, font=("Helvetica", 10))
        style.configure("TEntry", padding=5, font=("Helvetica", 10))
        style.configure("TButton", padding=5, font=("Helvetica", 10))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        
        # Frame principal avec scrollbar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Titre
        ttk.Label(scrollable_frame, text="Configuration de Nextcloud avec Docker et Traefik", 
                 style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=10)
        
        # Section Nextcloud
        ttk.Label(scrollable_frame, text="Configuration de Nextcloud", 
                 style="Header.TLabel").grid(row=1, column=0, columnspan=3, pady=10, sticky="w")
        
        ttk.Label(scrollable_frame, text="Nom de domaine Nextcloud:").grid(row=2, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.nextcloud_host, width=40).grid(row=2, column=1, sticky="w")
        ttk.Label(scrollable_frame, text="(ex: nextcloud.example.com)").grid(row=2, column=2, sticky="w")
        
        # Section Traefik
        ttk.Label(scrollable_frame, text="Configuration de Traefik", 
                 style="Header.TLabel").grid(row=3, column=0, columnspan=3, pady=10, sticky="w")
        
        ttk.Label(scrollable_frame, text="Nom de domaine Dashboard:").grid(row=4, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.traefik_dashboard_host, width=40).grid(row=4, column=1, sticky="w")
        ttk.Label(scrollable_frame, text="(ex: traefik.example.com)").grid(row=4, column=2, sticky="w")
        
        ttk.Label(scrollable_frame, text="Port du Dashboard:").grid(row=5, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.traefik_dashboard_port, width=40).grid(row=5, column=1, sticky="w")
        ttk.Label(scrollable_frame, text="(ex: 8080)").grid(row=5, column=2, sticky="w")
        
        ttk.Label(scrollable_frame, text="Email Let's Encrypt:").grid(row=6, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.traefik_acme_email, width=40).grid(row=6, column=1, sticky="w")
        ttk.Label(scrollable_frame, text="(pour les notifications SSL)").grid(row=6, column=2, sticky="w")
        
        ttk.Label(scrollable_frame, text="Niveau de logs:").grid(row=7, column=0, sticky="w")
        log_level_combo = ttk.Combobox(scrollable_frame, textvariable=self.traefik_log_level, 
                                      values=["DEBUG", "INFO", "WARN", "ERROR"], width=38)
        log_level_combo.grid(row=7, column=1, sticky="w")
        ttk.Label(scrollable_frame, text="(niveau de détail des logs)").grid(row=7, column=2, sticky="w")
        
        # Authentification Dashboard
        ttk.Label(scrollable_frame, text="Utilisateur Dashboard:").grid(row=8, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.traefik_dashboard_auth_user, width=40).grid(row=8, column=1, sticky="w")
        
        ttk.Label(scrollable_frame, text="Mot de passe Dashboard:").grid(row=9, column=0, sticky="w")
        password_frame = ttk.Frame(scrollable_frame)
        password_frame.grid(row=9, column=1, sticky="w")
        
        password_entry = ttk.Entry(password_frame, textvariable=self.traefik_dashboard_auth_password, width=30, show="*")
        password_entry.pack(side=tk.LEFT)
        
        def toggle_password():
            if password_entry['show'] == '*':
                password_entry['show'] = ''
                toggle_btn['text'] = 'Cacher'
            else:
                password_entry['show'] = '*'
                toggle_btn['text'] = 'Afficher'
        
        toggle_btn = ttk.Button(password_frame, text="Afficher", command=toggle_password, width=10)
        toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(scrollable_frame, text="Générer", command=lambda: self.traefik_dashboard_auth_password.set(self.generate_password(12))).grid(row=9, column=2, sticky="w")
        
        # Section Base de données
        ttk.Label(scrollable_frame, text="Configuration de la Base de Données", 
                 style="Header.TLabel").grid(row=10, column=0, columnspan=3, pady=10, sticky="w")
        
        ttk.Label(scrollable_frame, text="Nom de la base:").grid(row=11, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.mysql_database, width=40).grid(row=11, column=1, sticky="w")
        
        ttk.Label(scrollable_frame, text="Utilisateur:").grid(row=12, column=0, sticky="w")
        ttk.Entry(scrollable_frame, textvariable=self.mysql_user, width=40).grid(row=12, column=1, sticky="w")
        
        ttk.Label(scrollable_frame, text="Mot de passe utilisateur:").grid(row=13, column=0, sticky="w")
        user_pwd_frame = ttk.Frame(scrollable_frame)
        user_pwd_frame.grid(row=13, column=1, sticky="w")
        
        user_pwd_entry = ttk.Entry(user_pwd_frame, textvariable=self.mysql_password, width=30, show="*")
        user_pwd_entry.pack(side=tk.LEFT)
        
        def toggle_user_pwd():
            if user_pwd_entry['show'] == '*':
                user_pwd_entry['show'] = ''
                user_toggle_btn['text'] = 'Cacher'
            else:
                user_pwd_entry['show'] = '*'
                user_toggle_btn['text'] = 'Afficher'
        
        user_toggle_btn = ttk.Button(user_pwd_frame, text="Afficher", command=toggle_user_pwd, width=10)
        user_toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(scrollable_frame, text="Générer", command=lambda: self.mysql_password.set(self.generate_password())).grid(row=13, column=2, sticky="w")
        
        ttk.Label(scrollable_frame, text="Mot de passe root:").grid(row=14, column=0, sticky="w")
        root_pwd_frame = ttk.Frame(scrollable_frame)
        root_pwd_frame.grid(row=14, column=1, sticky="w")
        
        root_pwd_entry = ttk.Entry(root_pwd_frame, textvariable=self.mysql_root_password, width=30, show="*")
        root_pwd_entry.pack(side=tk.LEFT)
        
        def toggle_root_pwd():
            if root_pwd_entry['show'] == '*':
                root_pwd_entry['show'] = ''
                root_toggle_btn['text'] = 'Cacher'
            else:
                root_pwd_entry['show'] = '*'
                root_toggle_btn['text'] = 'Afficher'
        
        root_toggle_btn = ttk.Button(root_pwd_frame, text="Afficher", command=toggle_root_pwd, width=10)
        root_toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(scrollable_frame, text="Générer", command=lambda: self.mysql_root_password.set(self.generate_password())).grid(row=14, column=2, sticky="w")
        
        # Fuseau horaire
        ttk.Label(scrollable_frame, text="Autres paramètres", 
                 style="Header.TLabel").grid(row=15, column=0, columnspan=3, pady=10, sticky="w")
        
        ttk.Label(scrollable_frame, text="Fuseau horaire:").grid(row=16, column=0, sticky="w")
        timezones = [
            "Europe/Paris", "Europe/London", "Europe/Berlin", "Europe/Madrid", 
            "America/New_York", "America/Los_Angeles", "America/Chicago",
            "Asia/Tokyo", "Asia/Shanghai", "Asia/Singapore",
            "Australia/Sydney", "Pacific/Auckland"
        ]
        timezone_combo = ttk.Combobox(scrollable_frame, textvariable=self.timezone, values=timezones, width=38)
        timezone_combo.grid(row=16, column=1, sticky="w")
        
        # Boutons d'action
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.grid(row=17, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Charger .env existant", command=self.load_env_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Enregistrer", command=self.save_env_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Générer tous les mots de passe", command=self.generate_all_passwords).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Quitter", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
        # Informations supplémentaires
        info_text = """
        Cette application génère un fichier .env pour votre déploiement Nextcloud avec Docker et Traefik.
        
        Après avoir configuré tous les paramètres, cliquez sur "Enregistrer" pour créer le fichier .env.
        Ensuite, vous pourrez lancer votre déploiement avec la commande:
        
        docker-compose up -d
        
        Note: Assurez-vous que les noms de domaine que vous avez configurés pointent vers votre serveur.
        """
        
        info_label = ttk.Label(scrollable_frame, text=info_text, wraplength=650, justify="left")
        info_label.grid(row=18, column=0, columnspan=3, pady=10, sticky="w")
    
    def generate_password(self, length=16):
        """Génère un mot de passe aléatoire"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_-+=<>?"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_all_passwords(self):
        """Génère tous les mots de passe"""
        self.mysql_root_password.set(self.generate_password())
        self.mysql_password.set(self.generate_password())
        self.traefik_dashboard_auth_password.set(self.generate_password(12))
        messagebox.showinfo("Génération de mots de passe", "Tous les mots de passe ont été générés avec succès!")
    
    def load_env_file(self):
        """Charge les valeurs depuis un fichier .env existant"""
        try:
            env_file = ".env"
            if not os.path.exists(env_file):
                env_file = filedialog.askopenfilename(title="Sélectionner un fichier .env", filetypes=[("Fichiers .env", "*.env"), ("Tous les fichiers", "*.*")])
                if not env_file:
                    return
            
            with open(env_file, 'r') as f:
                env_content = f.read()
            
            # Extraire les valeurs avec des expressions régulières
            patterns = {
                'NEXTCLOUD_HOST': self.nextcloud_host,
                'TRAEFIK_DASHBOARD_HOST': self.traefik_dashboard_host,
                'TRAEFIK_DASHBOARD_PORT': self.traefik_dashboard_port,
                'TRAEFIK_ACME_EMAIL': self.traefik_acme_email,
                'TRAEFIK_LOG_LEVEL': self.traefik_log_level,
                'MYSQL_ROOT_PASSWORD': self.mysql_root_password,
                'MYSQL_PASSWORD': self.mysql_password,
                'MYSQL_DATABASE': self.mysql_database,
                'MYSQL_USER': self.mysql_user,
                'TRAEFIK_DASHBOARD_AUTH': self.traefik_dashboard_auth,
                'TZ': self.timezone
            }
            
            for key, var in patterns.items():
                pattern = r'^{}=(.*)$'.format(key)
                match = re.search(pattern, env_content, re.MULTILINE)
                if match:
                    value = match.group(1).strip()
                    # Supprimer les guillemets si présents
                    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    var.set(value)
            
            # Traitement spécial pour l'authentification du dashboard
            if self.traefik_dashboard_auth.get():
                auth_parts = self.traefik_dashboard_auth.get().split(':')
                if len(auth_parts) >= 1:
                    self.traefik_dashboard_auth_user.set(auth_parts[0])
                
                # Ne pas extraire le mot de passe haché, on garde celui généré ou défini par l'utilisateur
            
            messagebox.showinfo("Chargement", "Fichier .env chargé avec succès!")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chargement du fichier .env: {str(e)}")
    
    def generate_htpasswd(self):
        """Génère le hash htpasswd pour l'authentification du dashboard Traefik"""
        try:
            user = self.traefik_dashboard_auth_user.get()
            password = self.traefik_dashboard_auth_password.get()
            
            if not user or not password:
                messagebox.showerror("Erreur", "L'utilisateur et le mot de passe sont requis pour générer l'authentification.")
                return None
            
            # Essayer d'utiliser htpasswd si disponible
            try:
                if platform.system() == "Windows":
                    # Sur Windows, on utilise une méthode alternative
                    import base64
                    import hashlib
                    
                    salt = os.urandom(8)
                    hash_value = hashlib.md5(password.encode() + salt).digest()
                    apr1_hash = f"$apr1${base64.b64encode(salt).decode()[:8]}${base64.b64encode(hash_value).decode()[:22]}"
                    return f"{user}:{apr1_hash}"
                else:
                    # Sur Linux/Mac, on essaie d'utiliser htpasswd
                    result = subprocess.run(
                        ["htpasswd", "-nbB", user, password],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    # Remplacer $ par $$ pour docker-compose
                    return result.stdout.strip().replace("$", "$$")
            except:
                # Méthode de secours si htpasswd n'est pas disponible
                import base64
                import hashlib
                import secrets
                
                salt = secrets.token_hex(4)
                hashed = hashlib.md5(f"{password}{salt}".encode()).hexdigest()
                return f"{user}:$apr1${salt}${hashed}"
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la génération du hash htpasswd: {str(e)}")
            return None
    
    def save_env_file(self):
        """Enregistre les valeurs dans le fichier .env"""
        try:
            # Générer le hash htpasswd
            htpasswd = self.generate_htpasswd()
            if not htpasswd:
                return
            
            # Préparer le contenu du fichier .env
            env_content = f"""# Nom du projet (utilisé pour les noms des conteneurs et volumes)
COMPOSE_PROJECT_NAME=nextcloud-{self.nextcloud_host.get()}

# Configuration de la base de données
MYSQL_ROOT_PASSWORD={self.mysql_root_password.get()}
MYSQL_PASSWORD={self.mysql_password.get()}
MYSQL_DATABASE={self.mysql_database.get()}
MYSQL_USER={self.mysql_user.get()}

# Configuration de Nextcloud
NEXTCLOUD_HOST={self.nextcloud_host.get()}

# Configuration de Traefik
TRAEFIK_DASHBOARD_PORT={self.traefik_dashboard_port.get()}
TRAEFIK_DASHBOARD_HOST={self.traefik_dashboard_host.get()}
TRAEFIK_DASHBOARD_AUTH={htpasswd}
TRAEFIK_ACME_EMAIL={self.traefik_acme_email.get()}
TRAEFIK_LOG_LEVEL={self.traefik_log_level.get()}

# Fuseau horaire
TZ={self.timezone.get()}
"""
            
            # Enregistrer le fichier
            with open(".env", 'w') as f:
                f.write(env_content)
            
            # Vérifier si le répertoire traefik existe
            if not os.path.exists("traefik"):
                os.makedirs("traefik")
            
            # Créer le fichier acme.json s'il n'existe pas
            acme_path = os.path.join("traefik", "acme.json")
            if not os.path.exists(acme_path):
                with open(acme_path, 'w') as f:
                    f.write("{}")
                
                # Définir les permissions sur Unix-like
                if platform.system() != "Windows":
                    os.chmod(acme_path, 0o600)
            
            messagebox.showinfo("Succès", "Fichier .env enregistré avec succès!\n\nVous pouvez maintenant lancer votre déploiement avec:\ndocker-compose up -d")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'enregistrement du fichier .env: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EnvConfiguratorApp(root)
    root.mainloop() 