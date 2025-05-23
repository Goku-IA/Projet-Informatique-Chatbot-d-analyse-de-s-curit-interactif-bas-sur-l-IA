# exporter.py

from fpdf import FPDF
import os
import zipfile

def export_all(result_text_widget, code_text_widget, fix_text_widget, pdf_filepath="rapport.pdf"):
    """
    Exporte le contenu affiché dans l'interface directement dans un fichier PDF en utilisant
    la police Unicode DejaVu Sans pour supporter les caractères étendus (ex: "❌").

    Args:
        result_text_widget: Widget Tkinter contenant le texte des résultats.
        code_text_widget: Widget Tkinter contenant le code théorique.
        fix_text_widget: Widget Tkinter contenant les solutions correctives.
        pdf_filepath (str): Chemin du fichier PDF à générer.

    Returns:
        str: Le chemin du fichier PDF créé.
    """
    # Récupération du contenu des widgets
    result_content = result_text_widget.get("1.0", "end-1c")
    code_content = code_text_widget.get("1.0", "end-1c")
    fix_content = fix_text_widget.get("1.0", "end-1c")

    # Création du document PDF
    pdf = FPDF()
    pdf.add_page()

    # Ajout de la police Unicode DejaVu Sans.
    # Comme vous avez placé "DejaVuSans.ttf" dans le même répertoire que ce fichier,
    # nous pouvons utiliser directement le nom du fichier.
    pdf.add_font("DejaVu", "", "DejaVuSans.ttf", uni=True)
    pdf.set_font("DejaVu", size=12)

    # Insertion des contenus sur différentes pages
    pdf.multi_cell(0, 10, result_content)

    pdf.add_page()
    pdf.multi_cell(0, 10, code_content)

    pdf.add_page()
    pdf.multi_cell(0, 10, fix_content)

    # Sauvegarde du fichier PDF
    pdf.output(pdf_filepath)
    return pdf_filepath

def zip_report(pdf_filepath, zip_filepath="rapport.zip"):
    """
    Compresse le fichier PDF généré dans une archive ZIP.

    Args:
        pdf_filepath (str): Chemin du fichier PDF à compresser.
        zip_filepath (str): Chemin du fichier ZIP à créer.

    Returns:
        str: Le chemin du fichier ZIP créé.
    """
    with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(pdf_filepath, os.path.basename(pdf_filepath))
    return zip_filepath

if __name__ == "__main__":
    # Bloc de test : Simulation de widgets Tkinter avec une classe DummyWidget
    class DummyWidget:
        def __init__(self, text):
            self.text = text
        def get(self, start, end):
            return self.text

    # Création d'exemples de widgets
    result_text_dummy = DummyWidget("Ceci est le contenu des résultats de l'analyse ✨❌")
    code_text_dummy   = DummyWidget("Exemple de code théorique d'exploitation.\nprint('Hello World ❌')")
    fix_text_dummy    = DummyWidget("Exemple de solution corrective.\nCorriger les erreurs détectées ❌")

    # Génération du PDF et compression
    pdf_file = export_all(result_text_dummy, code_text_dummy, fix_text_dummy, pdf_filepath="rapport_test.pdf")
    print(f"PDF exporté : {pdf_file}")

    zip_file = zip_report(pdf_file, zip_filepath="rapport_test.zip")
    print(f"Archive ZIP créée : {zip_file}")
