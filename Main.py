
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
from scanner import run_security_scan
from ia import get_attack_and_fix_advice
from exporter import export_all, zip_report
from typing import Dict, Any

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Stocke les derniers résultats d'analyse
latest_results: Dict[str, Any] = {}


def perform_security_scan() -> None:
    """Lance l'analyse de sécurité dans un thread dédié afin de ne pas bloquer l'interface."""
    threading.Thread(target=scan_thread, daemon=True).start()


def scan_thread() -> None:
    """
    Exécute l'analyse de sécurité pour l'URL saisie, met à jour la barre de progression,
    affiche les résultats formatés et récupère, le cas échéant, des conseils d'exploitation et des solutions.
    """
    global latest_results

    url = url_entry.get().strip()
    if not url or not url.startswith("http"):
        messagebox.showwarning("Erreur", "Veuillez entrer une URL valide (ex : https://exemple.com).")
        return

    # Réinitialisation de l'interface
    status_label.config(text="Analyse en cours…")
    progress_bar["value"] = 0
    progress_step = 12.5  # Simulation d'une progression en 8 étapes
    result_text.delete("1.0", tk.END)
    code_text.delete("1.0", tk.END)
    fix_text.delete("1.0", tk.END)

    # Progression avant le scan
    for i in range(4):
        progress_bar["value"] += progress_step
        root.update_idletasks()

    try:
        results = run_security_scan(url)
    except Exception as e:
        progress_bar.stop()
        status_label.config(text="Erreur durant l'analyse.")
        logger.exception("Erreur lors de l'exécution du scan")
        messagebox.showerror("Erreur", str(e))
        return

    # Progression après le scan
    for i in range(4):
        progress_bar["value"] += progress_step
        root.update_idletasks()

    latest_results = results
    progress_bar["value"] = 100
    status_label.config(text="Analyse terminée.")

    # Affichage des résultats formatés avec des emojis
    result_text.insert(tk.END, "=== Résultats de l'analyse ===\n\n", "header")
    
    # SECURITY_HEADERS
    sh = results.get("security_headers", {})
    result_text.insert(tk.END, "[SECURITY_HEADERS]\n", "section")
    if sh.get("missing_headers"):
        result_text.insert(tk.END, "❌ En-têtes manquants :\n", "red")
        for hdr in sh["missing_headers"]:
            result_text.insert(tk.END, f"   - {hdr}\n", "red")
    else:
        result_text.insert(tk.END, "✅ Tous les en-têtes de sécurité sont présents.\n", "green")
    result_text.insert(tk.END, "\n")
    
    # SENSITIVE_FILES
    sf = results.get("sensitive_files", {})
    result_text.insert(tk.END, "[SENSITIVE_FILES]\n", "section")
    if sf.get("exposed_files"):
        result_text.insert(tk.END, "❌ Fichiers sensibles exposés :\n", "red")
        for f in sf["exposed_files"]:
            result_text.insert(tk.END, f"   - {f}\n", "red")
    else:
        result_text.insert(tk.END, "✅ Aucun fichier sensible exposé.\n", "green")
    result_text.insert(tk.END, "\n")
    
    # ADMIN_PAGES
    ap = results.get("admin_pages", {})
    result_text.insert(tk.END, "[ADMIN_PAGES]\n", "section")
    if ap.get("exposed_admin_pages"):
        result_text.insert(tk.END, "❌ Pages d'administration exposées :\n", "red")
        for page in ap["exposed_admin_pages"]:
            result_text.insert(tk.END, f"   - {page}\n", "red")
    else:
        result_text.insert(tk.END, "✅ Aucune page d'administration exposée détectée.\n", "green")
    result_text.insert(tk.END, "\n")
    
    # CSRF
    csrf = results.get("csrf", {})
    result_text.insert(tk.END, "[CSRF]\n", "section")
    if csrf.get("csrf_protection"):
        result_text.insert(tk.END, "✅ Protection CSRF détectée.\n", "green")
    else:
        result_text.insert(tk.END, "❌ Aucune protection CSRF détectée.\n", "red")
    result_text.insert(tk.END, "\n")
    
    # INDEXING
    idx = results.get("indexing", {})
    result_text.insert(tk.END, "[INDEXING]\n", "section")
    robots_txt = idx.get("robots_txt", "")
    if "Disallow:" in robots_txt:
        result_text.insert(tk.END, "✅ robots.txt restreint l'indexation.\n", "green")
    else:
        result_text.insert(tk.END, "⚠️ robots.txt permet l'indexation générale.\n", "orange")
    result_text.insert(tk.END, "\n")
    
    # SSL_CERTIFICATE
    ssl_cert = results.get("ssl_certificate", {})
    result_text.insert(tk.END, "[SSL_CERTIFICATE]\n", "section")
    result_text.insert(tk.END, f"🔒 {ssl_cert.get('status', '')}\n", "blue")
    result_text.insert(tk.END, "\n")
    
        # Récupération des conseils complémentaires fournis par l'IA
    # Récupération des conseils complémentaires fournis par l'IA
    advice = get_attack_and_fix_advice(results)

    # Initialisation des buffers pour le code et les solutions
    code_buffer = []
    fix_buffer = []
    current = None
    for line in advice.splitlines():
        stripped_line = line.strip()  # Nettoyage de la ligne
        if stripped_line == "=== CODE ===":
            current = "code"
            continue
        elif stripped_line == "=== SOLUTION ===":
            current = "fix"
            continue
        if current == "code":
            code_buffer.append(line)
        elif current == "fix":
            fix_buffer.append(line)

    # S'il n'y a aucune section détectée, utilisez un fallback avec l'avis complet
    if not code_buffer and not fix_buffer:
        print("Aucun délimiteur trouvé dans la réponse de l'IA.")
        code_buffer = [advice]
        fix_buffer = [advice]

    # Affichage dans les zones dédiées
    code_text.delete("1.0", tk.END)
    code_text.insert(tk.END, "\n".join(code_buffer).strip())

    fix_text.delete("1.0", tk.END)
    fix_text.insert(tk.END, "\n".join(fix_buffer).strip())


# Fonction d'exportation
def save_report():
    # Vérifiez que vos widgets ne sont pas vides ou que des données ont été générées.
    if result_text.get("1.0", "end-1c").strip() == "":
        messagebox.showwarning("Alerte", "Aucun résultat à exporter.")
        return

    # Exportation du contenu dans un PDF
    pdf_path = export_all(result_text, code_text, fix_text, pdf_filepath="rapport.pdf")
    
    # Compression du PDF en ZIP (si nécessaire)
    zip_path = zip_report(pdf_path, zip_filepath="rapport.zip")
    
    if zip_path:
        messagebox.showinfo("Succès", f"Exportation réussie : {zip_path}")
    else:
        messagebox.showerror("Erreur", "L'exportation a échoué.")


# [Le code existant jusqu'à la configuration de l'interface graphique reste inchangé...]

# --- Nouvelle configuration améliorée de l'interface graphique ---
root = tk.Tk()
root.title("🔍 Analyse de sécurité Web assistée par IA - Security Scanner")
root.geometry("1300x750")
root.eval('tk::PlaceWindow . center')  # Centrage automatique

# Style moderne avec ttk
style = ttk.Style()
style.theme_use('clam')  # Thème plus moderne que le thème par défaut

# Couleurs modernes
bg_color = "#f0f2f5"
primary_color = "#4a6fa5"
secondary_color = "#166d67"
text_color = "#333333"

# Configuration du style
style.configure('TFrame', background=bg_color)
style.configure('TLabel', background=bg_color, foreground=text_color)
style.configure('TButton', font=('Arial', 10), padding=6)
style.configure('TEntry', font=('Arial', 10), padding=5)
style.configure('Horizontal.TProgressbar', thickness=15, troughcolor='#e0e0e0', background=secondary_color)

# Appliquer le fond à la fenêtre principale
root.configure(bg=bg_color)

# Zone de saisie URL et boutons - Version améliorée
top_frame = ttk.Frame(root, padding=(10, 10))
top_frame.pack(fill=tk.X, pady=(10, 5))
ttk.Label(top_frame, text="🌐 URL à analyser :", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 5))

url_entry = ttk.Entry(top_frame, width=70, font=('Arial', 10))
url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))

scan_btn = ttk.Button(top_frame, text="🔍 Lancer l'analyse", command=perform_security_scan, style='primary.TButton')
scan_btn.pack(side=tk.LEFT)

export_btn = ttk.Button(top_frame, text="💾 Exporter le rapport", command=save_report)
export_btn.pack(side=tk.LEFT, padx=(10, 0))

# Style personnalisé pour le bouton principal
style.configure('primary.TButton', foreground='white', background=primary_color, font=('Arial', 10, 'bold'))
style.map('primary.TButton', background=[('active', primary_color), ('disabled', '#cccccc')])

# Statut et barre de progression - Version améliorée
status_frame = ttk.Frame(root)
status_frame.pack(fill=tk.X, pady=(5, 0), padx=10)

status_label = ttk.Label(status_frame, text="🟢 Prêt à analyser", font=('Arial', 9))
status_label.pack(side=tk.LEFT)

progress_bar = ttk.Progressbar(status_frame, mode="determinate", length=700, style='Horizontal.TProgressbar')
progress_bar.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(10, 0))

# Conteneur principal pour les résultats
main_pane = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

# Fonction pour créer un cadre de texte avec style cohérent
def create_text_frame(parent, title, bg_color):
    frame = ttk.Frame(parent, padding=5)
    
    # Header du cadre
    header = ttk.Frame(frame)
    header.pack(fill=tk.X, pady=(0, 5))
    ttk.Label(header, text=title, font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
    
    # Zone de texte
    text_widget = tk.Text(frame, wrap=tk.WORD, bg=bg_color, font=('Consolas', 10), 
                         padx=10, pady=10, relief=tk.FLAT, highlightthickness=1,
                         highlightbackground="#cccccc", highlightcolor=primary_color)
    text_widget.pack(fill=tk.BOTH, expand=True)
    
    # Ajout d'une barre de défilement
    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.config(yscrollcommand=scrollbar.set)
    
    return frame, text_widget

# Création des trois panneaux de résultats
res_frame, result_text = create_text_frame(main_pane, "📊 Résultats de l'analyse", "#ffffff")
main_pane.add(res_frame, weight=1)

code_frame, code_text = create_text_frame(main_pane, "💻 Exemples de code", "#fff9e6")
main_pane.add(code_frame, weight=1)

fix_frame, fix_text = create_text_frame(main_pane, "🛠️ Solutions recommandées", "#f0f9f5")
main_pane.add(fix_frame, weight=1)

# Configuration des tags pour la coloration dans result_text (amélioré)
font_bold = ('Arial', 10, 'bold')
result_text.tag_configure("header", font=('Arial', 11, 'bold'), foreground=primary_color, spacing3=5)
result_text.tag_configure("section", font=font_bold, foreground=secondary_color, spacing1=10, spacing3=5)
result_text.tag_configure("red", foreground="#d32f2f")  # Rouge plus moderne
result_text.tag_configure("green", foreground="#388e3c")  # Vert plus moderne
result_text.tag_configure("orange", foreground="#f57c00")  # Orange plus moderne
result_text.tag_configure("blue", foreground="#1976d2")  # Bleu plus moderne

# Ajout d'un pied de page
footer = ttk.Frame(root)
footer.pack(fill=tk.X, pady=(0, 5))
ttk.Label(footer, text="🔒 Security Scanner v1.0 - IA-Assisted Web Security Analysis", 
          font=('Arial', 8), foreground="#666666").pack(side=tk.RIGHT, padx=10)

# [Le reste du code existant reste inchangé...]

# Bouton d'export du rapport (PDF + ZIP)
tk.Button(root, text="Exporter le rapport (PDF + ZIP)", command=save_report).pack(pady=(0, 10))

# Démarrage de l'interface principale
root.mainloop()

