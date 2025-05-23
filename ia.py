"""
Module IA pour génération de rapport de vulnérabilités avec explication et codes théoriques.

Ce module structure les résultats d'analyse de sécurité en vulnérabilités enrichies, génère des 
rapports pédagogiques en Markdown et interagit avec un modèle IA local (ex. Ollama) afin de fournir
des conseils détaillés sur la sécurisation des failles détectées.
"""

import requests
import logging
from typing import Dict, List, Any

# Configuration du serveur IA local (Ollama)
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "openhermes:latest"

# Mappage de gravité par défaut pour chaque type de vulnérabilité détectée
SEVERITY_MAP: Dict[str, str] = {
    'csrf': 'Critique',
    'admin_pages': 'Critique',
    'sensitive_files': 'Critique',
    'security_headers': 'Important',
    'indexing': 'Mineur'
}

# Mappage du score CVSS en fonction de la gravité
CVSS_MAP: Dict[str, str] = {
    'Critique': 'CVSS 9.0-10.0',
    'Important': 'CVSS 7.0-8.9',
    'Mineur': 'CVSS 4.0-6.9'
}

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def build_structured_vulnerabilities(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Transforme les résultats d'analyse en une liste d'objets vulnérabilités enrichis avec analyse,
    recommandations, étapes théoriques d'exploitation et exemples de correctifs.
    
    Paramètres:
      - results (dict): Dictionnaire des résultats d'analyse de sécurité.
    
    Retourne:
      - List[Dict[str, Any]]: Liste de vulnérabilités structurées.
    """
    vulnerabilities = []

    for key, data in results.items():
        severity = SEVERITY_MAP.get(key, 'Mineur')
        cvss = CVSS_MAP.get(severity, 'CVSS 4.0-6.9')
        title = key.replace('_', ' ').capitalize()
        short_desc = str(data)

        vuln = {
            "title": title,
            "impact": severity,
            "cvss": cvss,
            "risk_description": f"Cette vulnérabilité peut poser des risques spécifiques : {short_desc}",
            "attack_steps": [
                f"Analyser le site pour détecter une faille de type {title}.",
                "Construire une preuve de concept (PoC) théorique sans impact réel.",
                "Préparer une stratégie de mitigation ou de correction."
            ],
            "attack_code": [
                f"# Exemple de code théorique pour exploiter {title}",
                "# Ce code ne doit pas être utilisé dans un environnement non autorisé.",
                "print('Simulation d’exploitation pour démonstration uniquement')"
            ],
            "fixes": [
                {
                    "name": "Correction standard",
                    "advantages": "Réduction durable du risque",
                    "disadvantages": "Peut nécessiter des modifications de code"
                },
                {
                    "name": "Mitigation temporaire",
                    "advantages": "Déploiement rapide",
                    "disadvantages": "Pas une solution définitive"
                }
            ],
            "best_fix": "Correction standard",
            "fix_code": [
                f"# Exemple de code correctif pour {title}",
                "# Ajouter des validations côté serveur / headers de sécurité, etc."
            ]
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


def generate_attack_scenarios(vulnerabilities: List[Dict[str, Any]]) -> str:
    """
    Génère un rapport structuré en Markdown détaillant chaque vulnérabilité, incluant les 
    descriptions, étapes d'exploitation théoriques, exemples de code d'attaque et de correctif,
    ainsi que les recommandations.
    
    Paramètres:
      - vulnerabilities (List[Dict[str, Any]]): Liste de vulnérabilités structurées.
    
    Retourne:
      - str: Rapport complet formaté en Markdown.
    """
    report_lines = [
        "# Rapport de Sécurité Web",
        "",
        "## Table des matières"
    ]
    for vuln in vulnerabilities:
        anchor = vuln['title'].lower().replace(' ', '-')
        report_lines.append(f"- [{vuln['title']}](#{anchor})")
    report_lines.append("\n---\n")
    
    for vuln in vulnerabilities:
        report_lines.extend([
            f"## Vulnérabilité : {vuln['title']}",
            "",
            f"**Gravité** : {vuln['impact']} ({vuln['cvss']})",
            "",
            f"**Description** : {vuln['risk_description']}",
            "",
            "### Étapes théoriques d'exploitation"
        ])
        for idx, step in enumerate(vuln['attack_steps'], 1):
            report_lines.append(f"{idx}. {step}")
        report_lines.extend([
            "",
            "### Code pour exploiter la vulnérabilité (exemple théorique)",
            "```python"
        ])
        report_lines.extend(vuln['attack_code'])
        report_lines.extend([
            "```",
            "",
            "### Correctifs proposés",
            "",
            "| Solution | Avantages | Inconvénients |",
            "|:--------:|:----------|:--------------|"
        ])
        for fix in vuln['fixes']:
            report_lines.append(f"| {fix['name']} | {fix['advantages']} | {fix['disadvantages']} |")
        report_lines.extend([
            "",
            f"**Choix recommandé** : {vuln['best_fix']}",
            "",
            "```python"
        ])
        report_lines.extend(vuln['fix_code'])
        report_lines.extend([
            "```",
            "\n---\n"
        ])
    
    return "\n".join(report_lines)


def build_attack_prompt(results: dict) -> str:
    """
    Construit un prompt destiné à l'IA (Ollama) pour générer un rapport d'analyse de sécurité
    strictement formaté. Pour chaque vulnérabilité détectée dans "results", la réponse de l'IA
    DOIT contenir UNIQUEMENT le contenu demandé avec les délimiteurs EXACTS "=== CODE ==="
    et "=== SOLUTION ===", sans texte additionnel (pas d'introduction, de conclusion ou de commentaires).

    Format requis (exemple générique) :

    -----------------------------------------------------------
    ## Vulnérabilité : [Nom de la vulnérabilité]
    - Gravité : [Niveau] (CVSS: [Valeur])
    - Description : [Description technique succincte]

    === CODE ===
    ```python
    # Exemple de code d'exploitation théorique
    ```

    === SOLUTION ===
    [Explication technique détaillée, incluant des options et exemples de correctifs]
    -----------------------------------------------------------

    IMPORTANT : Répondez UNIQUEMENT en utilisant ce format.
    """
    prompt_lines = []

    # -------------------------------
    # PARTIE 1 : Instructions générales
    # -------------------------------
    prompt_lines.append("# Rapport d'analyse de sécurité")
    prompt_lines.append("")
    prompt_lines.append("Veuillez fournir l'analyse pour chaque vulnérabilité détectée en respectant EXACTEMENT le format ci-dessous.")
    prompt_lines.append("Ne fournissez aucune introduction, conclusion ou commentaire supplémentaire.")
    prompt_lines.append("")
    prompt_lines.append("FORMAT REQUIS :")
    prompt_lines.append("")
    prompt_lines.append("## Vulnérabilité : [Nom de la vulnérabilité]")
    prompt_lines.append("- Gravité : [Niveau] (CVSS: [Valeur])")
    prompt_lines.append("- Description : [Description technique succincte]")
    prompt_lines.append("")
    prompt_lines.append("=== CODE ===")
    prompt_lines.append("```python")
    prompt_lines.append("# Exemple de code d'exploitation théorique")
    prompt_lines.append("```")
    prompt_lines.append("")
    prompt_lines.append("=== SOLUTION ===")
    prompt_lines.append("[Explication technique détaillée, incluant des options et exemples de correctifs]")
    prompt_lines.append("")
    prompt_lines.append("IMPORTANT : La réponse renvoyée DOIT contenir UNIQUEMENT ce format, sans texte additionnel.")
    prompt_lines.append("")
    prompt_lines.append("Fournissez l'analyse pour l'ensemble des vulnérabilités identifiées ci-dessous :")
    prompt_lines.append("")

    # -------------------------------
    # PARTIE 2 : Exemple de vulnérabilité 1 - Absence de protection CSRF
    # -------------------------------
    if "csrf" in results and not results["csrf"].get("csrf_protection", True):
        prompt_lines.append("## Vulnérabilité : Absence de protection CSRF")
        prompt_lines.append("- Gravité : Critique (CVSS 9.0-10.0)")
        prompt_lines.append("- Description : Le formulaire n'intègre pas de jeton CSRF, facilitant les requêtes frauduleuses.")
        prompt_lines.append("")
        prompt_lines.append("=== CODE ===")
        prompt_lines.append("```python")
        prompt_lines.append("# Exploitation d'une absence de protection CSRF")
        prompt_lines.append("import requests")
        prompt_lines.append("def exploit_csrf(url, victim_cookie):")
        prompt_lines.append("    payload = {'new_password': 'hacked123'}")
        prompt_lines.append("    headers = {'Cookie': victim_cookie}")
        prompt_lines.append("    response = requests.post(url, data=payload, headers=headers)")
        prompt_lines.append("    print(f'CSRF possible ? Réponse : {response.status_code}')")
        prompt_lines.append("exploit_csrf('https://victime.com/update_password', 'sessionid=abc123')")
        prompt_lines.append("```")
        prompt_lines.append("")
        prompt_lines.append("=== SOLUTION ===")
        prompt_lines.append("Option 1 : Utiliser Flask-WTF pour gérer automatiquement les jetons CSRF.")
        prompt_lines.append("```python")
        prompt_lines.append("from flask import Flask, render_template")
        prompt_lines.append("from flask_wtf import FlaskForm, CSRFProtect")
        prompt_lines.append("from wtforms import PasswordField, SubmitField")
        prompt_lines.append("")
        prompt_lines.append("app = Flask(__name__)")
        prompt_lines.append("app.config['SECRET_KEY'] = 'votre_clé_très_secrète'")
        prompt_lines.append("csrf = CSRFProtect(app)")
        prompt_lines.append("")
        prompt_lines.append("class ChangePasswordForm(FlaskForm):")
        prompt_lines.append("    new_password = PasswordField('Nouveau mot de passe')")
        prompt_lines.append("    submit = SubmitField('Changer le mot de passe')")
        prompt_lines.append("")
        prompt_lines.append("@app.route('/update_password', methods=['GET', 'POST'])")
        prompt_lines.append("def update_password():")
        prompt_lines.append("    form = ChangePasswordForm()")
        prompt_lines.append("    if form.validate_on_submit():")
        prompt_lines.append("        # Traitement du changement de mot de passe")
        prompt_lines.append("        pass")
        prompt_lines.append("    return render_template('update_password.html', form=form)")
        prompt_lines.append("```")
        prompt_lines.append("Option 2 : Implémenter manuellement un jeton CSRF avec vérification côté serveur.")
        prompt_lines.append("```python")
        prompt_lines.append("import os, hmac, hashlib")
        prompt_lines.append("from flask import Flask, session, request, render_template")
        prompt_lines.append("")
        prompt_lines.append("app = Flask(__name__)")
        prompt_lines.append("app.secret_key = os.urandom(24)")
        prompt_lines.append("")
        prompt_lines.append("def generate_csrf_token():")
        prompt_lines.append("    token = hmac.new(app.secret_key, os.urandom(64), hashlib.sha256).hexdigest()")
        prompt_lines.append("    session['csrf_token'] = token")
        prompt_lines.append("    return token")
        prompt_lines.append("")
        prompt_lines.append("@app.route('/update_password', methods=['GET', 'POST'])")
        prompt_lines.append("def update_password():")
        prompt_lines.append("    if request.method == 'GET':")
        prompt_lines.append("        token = generate_csrf_token()")
        prompt_lines.append("        return render_template('update_password.html', csrf_token=token)")
        prompt_lines.append("    elif request.method == 'POST':")
        prompt_lines.append("        if request.form.get('csrf_token') != session.get('csrf_token'):")
        prompt_lines.append("            return 'Erreur CSRF', 400")
        prompt_lines.append("        # Traitement du changement de mot de passe")
        prompt_lines.append("        pass")
        prompt_lines.append("```")
        prompt_lines.append("")

    # -------------------------------
    # PARTIE 3 : Exemple de vulnérabilité 2 - Absence d'en-têtes de sécurité
    # -------------------------------
    if "security_headers" in results and results["security_headers"].get("missing_headers"):
        prompt_lines.append("## Vulnérabilité : Absence d'en-têtes de sécurité")
        prompt_lines.append("- Gravité : Important (CVSS 7.0-8.9)")
        prompt_lines.append("- Description : Les en-têtes essentiels tels que Strict-Transport-Security et X-Frame-Options sont absents, facilitant des attaques type clickjacking ou XSS.")
        prompt_lines.append("")
        prompt_lines.append("=== CODE ===")
        prompt_lines.append("```python")
        prompt_lines.append("# Exploitation de l'absence d'en-têtes de sécurité")
        prompt_lines.append("import requests")
        prompt_lines.append("def exploit_missing_headers(url):")
        prompt_lines.append("    res = requests.get(url)")
        prompt_lines.append("    if '<script>' in res.text.lower():")
        prompt_lines.append("        print('Injection XSS possible')")
        prompt_lines.append("    else:")
        prompt_lines.append("        print('Aucune injection détectée')")
        prompt_lines.append("exploit_missing_headers('https://victime.com')")
        prompt_lines.append("```")
        prompt_lines.append("")
        prompt_lines.append("=== SOLUTION ===")
        prompt_lines.append("Option 1 : Configurer les en-têtes de sécurité dans l'application (exemple avec Flask).")
        prompt_lines.append("```python")
        prompt_lines.append("@app.after_request")
        prompt_lines.append("def set_secure_headers(response):")
        prompt_lines.append("    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'")
        prompt_lines.append("    response.headers['X-Frame-Options'] = 'DENY'")
        prompt_lines.append("    response.headers['X-Content-Type-Options'] = 'nosniff'")
        prompt_lines.append("    response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'\"")
        prompt_lines.append("    return response")
        prompt_lines.append("```")
        prompt_lines.append("Option 2 : Configurer ces en-têtes via la configuration du serveur HTTP (exemple Apache).")
        prompt_lines.append("```apache")
        prompt_lines.append("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"")
        prompt_lines.append("Header always set X-Frame-Options \"DENY\"")
        prompt_lines.append("Header always set X-Content-Type-Options \"nosniff\"")
        prompt_lines.append("Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'\"")
        prompt_lines.append("```")
        prompt_lines.append("")

    # -------------------------------
    # PARTIE 4 : Exemple de vulnérabilité 3 - Configuration incorrecte de robots.txt
    # -------------------------------
    if "indexing" in results:
        prompt_lines.append("## Vulnérabilité : Configuration incorrecte de robots.txt")
        prompt_lines.append("- Gravité : Mineur (CVSS 4.0-6.9)")
        prompt_lines.append("- Description : Le fichier robots.txt est mal configuré et peut permettre l'indexation de répertoires sensibles.")
        prompt_lines.append("")
        prompt_lines.append("=== CODE ===")
        prompt_lines.append("```python")
        prompt_lines.append("# Vérification de la configuration de robots.txt")
        prompt_lines.append("import requests")
        prompt_lines.append("def check_robots(url):")
        prompt_lines.append("    response = requests.get(url + '/robots.txt')")
        prompt_lines.append("    if response.status_code == 200:")
        prompt_lines.append("        content = response.text")
        prompt_lines.append("        if 'Disallow:' not in content:")
        prompt_lines.append("            print('Indexation non restreinte')")
        prompt_lines.append("        else:")
        prompt_lines.append("            print('Indexation restreinte')")
        prompt_lines.append("    else:")
        prompt_lines.append("        print('Impossible d'accéder à robots.txt')")
        prompt_lines.append("check_robots('https://victime.com')")
        prompt_lines.append("```")
        prompt_lines.append("")
        prompt_lines.append("=== SOLUTION ===")
        prompt_lines.append("Option 1 : Créer un robots.txt correctement configuré qui interdit l'indexation des répertoires sensibles.")
        prompt_lines.append("```")
        prompt_lines.append("User-agent: *")
        prompt_lines.append("Disallow: /admin/")
        prompt_lines.append("Disallow: /config/")
        prompt_lines.append("Disallow: /private/")
        prompt_lines.append("```")
        prompt_lines.append("Option 2 : Utiliser les outils de votre plateforme d'hébergement ou CMS pour restreindre l'indexation.")
        prompt_lines.append("")

    # -------------------------------
    # PARTIE 5 : Exemple de vulnérabilité 4 - Certificat SSL proche de l'expiration
    # -------------------------------
    if "ssl_certificate" in results and results["ssl_certificate"].get("details", {}).get("days_until_expiry", 100) < 30:
        prompt_lines.append("## Vulnérabilité : Certificat SSL proche de l'expiration")
        prompt_lines.append("- Gravité : Important (CVSS 7.0-8.9)")
        prompt_lines.append("- Description : Le certificat SSL expire bientôt, ce qui peut entraîner des alertes de sécurité et une perte de confiance.")
        prompt_lines.append("")
        prompt_lines.append("=== CODE ===")
        prompt_lines.append("```python")
        prompt_lines.append("# Vérification de la validité du certificat SSL")
        prompt_lines.append("import ssl, socket")
        prompt_lines.append("def check_ssl_cert(hostname):")
        prompt_lines.append("    context = ssl.create_default_context()")
        prompt_lines.append("    with socket.create_connection((hostname, 443), timeout=5) as sock:")
        prompt_lines.append("        with context.wrap_socket(sock, server_hostname=hostname) as ssock:")
        prompt_lines.append("            cert = ssock.getpeercert()")
        prompt_lines.append("            print('Certificat émis par :', cert.get('issuer'))")
        prompt_lines.append("            print('Expire le :', cert.get('notAfter'))")
        prompt_lines.append("check_ssl_cert('victime.com')")
        prompt_lines.append("```")
        prompt_lines.append("")
        prompt_lines.append("=== SOLUTION ===")
        prompt_lines.append("Option 1 : Renouveler le certificat SSL via Certbot pour Let's Encrypt.")
        prompt_lines.append("```bash")
        prompt_lines.append("sudo certbot renew")
        prompt_lines.append("```")
        prompt_lines.append("Option 2 : Utiliser un service de gestion automatique de certificats pour éviter l'expiration.")
        prompt_lines.append("")

    return "\n".join(prompt_lines)



def generate_ia_advice(results: Dict[str, Any]) -> str:
    """
    Envoie le prompt construit à partir des résultats d'analyse au modèle IA local (Ollama)
    et récupère un rapport détaillé.
    
    Paramètres:
      - results (dict): Dictionnaire des résultats d'analyse de sécurité.
    
    Retourne:
      - str: Réponse du modèle IA ou message d'erreur en cas de problème.
    """
    prompt = build_attack_prompt(results)
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=500)
        response.raise_for_status()
        res_json = response.json()
        return res_json.get("response", "Erreur : aucune réponse IA reçue.")
    except Exception as e:
        logger.exception("Erreur lors de l'appel au modèle IA")
        return f"Erreur IA : {str(e)}"

def get_attack_and_fix_advice(results: Dict[str, Any]) -> str:
    return generate_ia_advice(results)
