# scanner.py
"""Module d'analyse de sécurité web – version améliorée

Ce module permet d'analyser différents aspects de la sécurité d'un site web,
vérifiant par exemple la présence d'en-têtes de sécurité, l'exposition de fichiers
sensibles, l'accès aux pages d'administration, la protection CSRF, la configuration
du fichier robots.txt, et la validité du certificat SSL pour les sites HTTPS.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import socket
import ssl
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Constantes ---
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin"
]

COMMON_ADMIN_PATHS = [
    "admin", "login", "wp-admin", "administrator", "admin.php", "cpanel", "dashboard"
]

COMMON_SENSITIVE_FILES = [
    ".env", ".git/config", "config.php", "config.json", "backup.zip", "db.sql", "phpinfo.php"
]

# En-tête HTTP personnalisé pour simuler un navigateur
HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def scan_security_headers(url):
    """
    Analyse la présence des en-têtes HTTP de sécurité sur la page.
    """
    try:
        resp = requests.get(url, timeout=5, headers=HTTP_HEADERS)
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        return {
            "title": "En-têtes HTTP de sécurité",
            "status": f"{len(missing)} en-tête(s) manquant(s)." if missing else "Tous les en-têtes critiques sont présents.",
            "missing_headers": missing,
            "details": missing,
            "recommendation": "Ajoutez les en-têtes manquants pour renforcer la sécurité côté client.",
            "severity": "Important" if missing else "Mineur"
        }
    except Exception as e:
        logger.exception("Erreur lors de la vérification des en-têtes")
        return {
            "title": "Erreur lors de la vérification des en-têtes",
            "status": str(e),
            "missing_headers": [],
            "details": [],
            "recommendation": "Assurez-vous que le site est accessible et fonctionne correctement.",
            "severity": "Mineur"
        }


def scan_sensitive_files(url):
    """
    Vérifie l'exposition de fichiers sensibles communément trouvés sur le serveur.
    """
    exposed = []
    for file_path in COMMON_SENSITIVE_FILES:
        target = urljoin(url, file_path)
        try:
            r = requests.get(target, timeout=3, headers=HTTP_HEADERS)
            if r.status_code == 200:
                exposed.append(target)
        except requests.RequestException:
            logger.debug(f"Impossible d'accéder au fichier: {target}")
            continue
    return {
        "title": "Fichiers sensibles exposés",
        "status": f"{len(exposed)} fichier(s) exposé(s) détecté(s)." if exposed else "Aucun fichier sensible trouvé.",
        "exposed_files": exposed,
        "details": exposed,
        "recommendation": "Supprimez ou protégez l’accès à ces fichiers sensibles.",
        "severity": "Critique" if exposed else "Mineur"
    }


def scan_admin_pages(url):
    """
    Recherche l'exposition des pages d'administration communes.
    """
    exposed = []
    for path in COMMON_ADMIN_PATHS:
        target = urljoin(url, path)
        try:
            r = requests.get(target, timeout=3, headers=HTTP_HEADERS)
            if r.status_code in (200, 403):
                exposed.append(target)
        except requests.RequestException:
            logger.debug(f"Impossible d'accéder à la page: {target}")
            continue
    return {
        "title": "Pages d'administration accessibles",
        "status": f"{len(exposed)} page(s) d'administration potentiellement exposée(s)." if exposed else "Aucune page sensible détectée.",
        "exposed_admin_pages": exposed,
        "details": exposed,
        "recommendation": "Restreignez l’accès aux interfaces d’administration via authentification ou IP whitelist.",
        "severity": "Critique" if exposed else "Mineur"
    }


def scan_csrf(url):
    """
    Analyse la présence d'une protection CSRF en inspectant les formulaires de la page.
    """
    try:
        resp = requests.get(url, timeout=5, headers=HTTP_HEADERS)
        soup = BeautifulSoup(resp.text, 'html.parser')
        tokens = []
        for form in soup.find_all('form'):
            for inp in form.find_all('input'):
                name = inp.get('name', '').lower()
                if 'csrf' in name or 'token' in name:
                    tokens.append(name)
        if tokens:
            return {
                "title": "Protection CSRF",
                "status": "Protection CSRF détectée.",
                "csrf_protection": True,
                "details": list(set(tokens)),
                "recommendation": "Vérifiez que le jeton CSRF est bien vérifié côté serveur.",
                "severity": "Important"
            }
        else:
            return {
                "title": "Absence de protection CSRF",
                "status": "Aucune protection CSRF détectée.",
                "csrf_protection": False,
                "details": [],
                "recommendation": "Ajoutez une protection CSRF pour les formulaires sensibles.",
                "severity": "Critique"
            }
    except Exception as e:
        logger.exception("Erreur lors de l'analyse CSRF")
        return {
            "title": "Erreur CSRF",
            "status": f"Erreur d'analyse CSRF : {str(e)}",
            "csrf_protection": None,
            "details": [],
            "recommendation": "Vérifiez la disponibilité du site.",
            "severity": "Mineur"
        }


def scan_indexing(url):
    """
    Vérifie la présence du fichier robots.txt pour détecter d'éventuelles fuites d'informations.
    """
    try:
        robots_url = urljoin(url, '/robots.txt')
        resp = requests.get(robots_url, timeout=5, headers=HTTP_HEADERS)
        robots_text = resp.text.strip()
        return {
            "title": "Indexation (robots.txt)",
            "status": "Fichier robots.txt trouvé.",
            "robots_txt": robots_text,
            "details": robots_text.splitlines(),
            "recommendation": "Vérifiez que le fichier ne divulgue pas d’informations sensibles.",
            "severity": "Mineur"
        }
    except requests.RequestException:
        return {
            "title": "Indexation (robots.txt)",
            "status": "Fichier robots.txt introuvable ou inaccessible.",
            "robots_txt": "",
            "details": [],
            "recommendation": "Ajoutez un fichier robots.txt si nécessaire.",
            "severity": "Mineur"
        }


def scan_ssl_certificate(url):
    """
    Analyse la validité du certificat SSL pour les sites HTTPS.
    Pour une URL en HTTP, l'analyse SSL n'est pas applicable.
    """
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        return {
            "title": "Certificat SSL",
            "status": "L'URL n'utilise pas HTTPS.",
            "details": [],
            "recommendation": "Utilisez HTTPS pour sécuriser la communication.",
            "severity": "Mineur"
        }
    
    host = parsed_url.hostname
    port = parsed_url.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Extraction des informations clés du certificat
                subject = dict(x[0] for x in cert.get('subject', ()))
                issued_to = subject.get('commonName', '')
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                issued_by = issuer.get('commonName', '')
                valid_from = cert.get('notBefore', 'N/A')
                valid_to = cert.get('notAfter', 'N/A')
                # Tentative de conversion de la date d'expiration
                try:
                    expiry_date = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry_date - datetime.utcnow()).days
                except Exception:
                    days_left = None
                details = {
                    "issued_to": issued_to,
                    "issued_by": issued_by,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "days_until_expiry": days_left
                }
                status_message = "Certificat SSL valide."
                if days_left is not None and days_left < 30:
                    status_message = "Le certificat SSL expire bientôt."
                return {
                    "title": "Certificat SSL",
                    "status": status_message,
                    "details": details,
                    "recommendation": "Renouvelez le certificat avant son expiration." if days_left is not None and days_left < 30 else "Le certificat est valide.",
                    "severity": "Critique" if days_left is not None and days_left < 30 else "Mineur"
                }
    except Exception as e:
        logger.exception("Erreur lors de la vérification du certificat SSL")
        return {
            "title": "Certificat SSL",
            "status": f"Erreur: {str(e)}",
            "details": [],
            "recommendation": "Vérifiez la connectivité et la configuration SSL du serveur.",
            "severity": "Critique"
        }


def run_security_scan(url):
    """
    Exécute l'ensemble des analyses de sécurité sur l'URL spécifiée.
    Renvoie un dictionnaire regroupant les résultats de chaque analyse.
    """
    return {
        "security_headers": scan_security_headers(url),
        "sensitive_files": scan_sensitive_files(url),
        "admin_pages": scan_admin_pages(url),
        "csrf": scan_csrf(url),
        "indexing": scan_indexing(url),
        "ssl_certificate": scan_ssl_certificate(url)
    }
