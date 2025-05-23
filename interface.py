import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import re
import validators
from scanner import run_security_scan  # Doit gérer les étapes de progression et exceptions
from ia import get_attack_and_fix_advice
from exporter import export_all

class WebScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de sécurité")

        # Utilisation de grid pour un design plus responsive
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        top_frame = tk.Frame(self.root)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        tk.Label(top_frame, text="URL à scanner :").grid(row=0, column=0, padx=5)
        self.url_entry = tk.Entry(top_frame, width=80)
        self.url_entry.grid(row=0, column=1, padx=5)
        scan_button = tk.Button(top_frame, text="Lancer Scan", command=self.start_scan_thread)
        scan_button.grid(row=0, column=2, padx=5)
        export_button = tk.Button(top_frame, text="Exporter rapport", command=self.export_report)
        export_button.grid(row=0, column=3, padx=5)

        self.result_box = ScrolledText(self.root, width=100, height=20)
        self.result_box.grid(row=1, column=0, sticky="nsew", padx=10)

        self.progress = ttk.Progressbar(self.root, length=200, mode='determinate')
        self.progress.grid(row=2, column=0, pady=10)

        tk.Label(self.root, text="Code théorique d'exploitation", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", padx=10)
        self.code_box = ScrolledText(self.root, width=100, height=8)
        self.code_box.grid(row=4, column=0, sticky="nsew", padx=10)

        tk.Label(self.root, text="Conseils et correctifs", font=("Segoe UI", 10, "bold")).grid(row=5, column=0, sticky="w", padx=10)
        self.solution_box = ScrolledText(self.root, width=100, height=8)
        self.solution_box.grid(row=6, column=0, sticky="nsew", padx=10)

        self.results_data = {}

    def append_text(self, text, tag=None, widget=None):
        if widget is None:
            widget = self.result_box
        widget.insert(tk.END, text)
        if tag:
            widget.tag_add(tag, f"end-{len(text)}c", tk.END)
            if tag == "red":
                widget.tag_config(tag, foreground="red")
            elif tag == "green":
                widget.tag_config(tag, foreground="green")
            elif tag == "orange":
                widget.tag_config(tag, foreground="orange")
            elif tag == "blue":
                widget.tag_config(tag, foreground="blue")
            elif tag == "bold":
                widget.tag_config(tag, font=("Segoe UI", 10, "bold"))
            elif tag == "section":
                widget.tag_config(tag, foreground="black", font=("Segoe UI", 10, "bold"))
            elif tag == "boldred":
                widget.tag_config(tag, foreground="red", font=("Segoe UI", 10, "bold"))
        widget.see(tk.END)

    def evaluate_severity(self):
        critical = moderate = False
        r = self.results_data
        if r.get("security_headers", {}).get("missing_headers"):
            critical = True
        if not r.get("csrf", {}).get("csrf_protection", True):
            critical = True
        if r.get("admin_pages", {}).get("exposed_admin_pages"):
            moderate = True
        if r.get("sensitive_files", {}).get("exposed_files"):
            critical = True
        return "CRITIQUE" if critical else "MOYEN" if moderate else "FAIBLE"

    def validate_url(self, url):
        return validators.url(url) and url.startswith("https://")

    def run_scan(self, url):
        try:
            self.append_text(f"[+] Lancement de l'analyse de sécurité pour : {url}\n", "blue")
            self.progress["value"] = 0
            self.root.update_idletasks()

            self.results_data = run_security_scan(url, progress_callback=self.update_progress)
            self.progress["value"] = 100
            self.display_results()

        except Exception as e:
            self.append_text(f"Erreur lors du scan : {str(e)}\n", "red")
            messagebox.showerror("Erreur", f"Erreur pendant l'analyse : {e}")

    def update_progress(self, percent):
        self.progress["value"] = percent
        self.root.update_idletasks()

    def start_scan_thread(self):
        url = self.url_entry.get().strip()
        if not url or not self.validate_url(url):
            messagebox.showwarning("Alerte", "Veuillez entrer une URL valide et sécurisée (https://...).")
            return
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def display_results(self):
        self.append_text("\n=== Résultats de l'analyse ===\n", "bold")
        self.code_box.delete("1.0", tk.END)
        self.solution_box.delete("1.0", tk.END)

        for section, result in self.results_data.items():
            self.append_text(f"\n[{section.upper()}]\n", "section")
            if result.get("status") == "error":
                self.append_text(f"  Erreur : {result.get('message')}\n", "red")
                continue
            if section == "security_headers":
                headers = result.get("missing_headers", [])
                if headers:
                    for h in headers:
                        self.append_text(f"  ❌ Header manquant : {h}\n", "red")
                else:
                    self.append_text("  ✅ Tous les headers de sécurité sont présents.\n", "green")
            elif section == "csrf":
                if result.get("csrf_protection", True):
                    self.append_text("  ✅ Protection CSRF détectée.\n", "green")
                else:
                    self.append_text("  ❌ Aucune protection CSRF détectée.\n", "red")
            elif section == "admin_pages":
                pages = result.get("exposed_admin_pages", [])
                if pages:
                    for page in pages:
                        self.append_text(f"  ❌ Page admin exposée : {page}\n", "orange")
                else:
                    self.append_text("  ✅ Aucune page admin exposée détectée.\n", "green")
            elif section == "sensitive_files":
                files = result.get("exposed_files", [])
                if files:
                    for f in files:
                        self.append_text(f"  ❌ Fichier critique exposé : {f}\n", "red")
                else:
                    self.append_text("  ✅ Aucun fichier critique exposé.\n", "green")
            elif section == "indexing":
                txt = result.get("robots_txt", "")
                if "Disallow: /" in txt:
                    self.append_text("  ✅ Indexation par Google restreinte dans robots.txt.\n", "green")
                else:
                    self.append_text("  ⚠️ robots.txt permet l'indexation générale.\n", "orange")
            elif section == "ssl_certificate":
                status = result.get("status", "")
                self.append_text(f"  {status}\n", "blue")

        self.append_text("\nRésumé de gravité :\n", "bold")
        level = self.evaluate_severity()
        tag = "boldred" if level == "CRITIQUE" else "orange" if level == "MOYEN" else "green"
        self.append_text(f"  Niveau global de vulnérabilité : {level}\n", tag)

        markdown = get_attack_and_fix_advice(self.results_data)
        self.display_advice(markdown)

    def display_advice(self, markdown):
        if not markdown:
            return
        in_code = False
        for line in markdown.splitlines():
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            tag = "bold" if line.strip().startswith("#") else None
            if in_code:
                self.append_text(line + "\n", widget=self.code_box)
            else:
                self.append_text(line + "\n", widget=self.solution_box, tag=tag)

    def export_report(self):
        if not self.results_data:
            messagebox.showwarning("Alerte", "Aucun résultat à exporter.")
            return
        try:
            export_all(self.results_data)
            messagebox.showinfo("Export", "Le rapport a été exporté avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur export : {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebScannerApp(root)
    root.mainloop()
