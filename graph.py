from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(total_score, explanations, scores, output_path="report.pdf"):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # 1. Score global avec couleur
    if total_score <= 14:
        color, level = colors.green, "Probablement légitime"
    elif total_score <= 20:
        color, level = colors.yellow, "À surveiller"
    elif total_score <= 45:
        color, level = colors.orange, "Suspect"
    else:
        color, level = colors.red, "Hautement suspect"
    
    # Titre avec score
    title = Paragraph(f"<font size=24 color={color}>Score : {total_score}</font><br/>{level}", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # 2. Explication de la fourchette
    explanation_text = get_explanation_for_score(total_score)
    story.append(Paragraph(explanation_text, styles['BodyText']))
    story.append(Spacer(1, 12))
    
    # 3. Tableau des anomalies
    table_data = [["Anomalie", "Score", "Explication"]]
    cpt = 0
    anomalies_nb = len(scores)
    #for score, msg in scores,explanations:
    #    table_data.append(["msg[:40]", str(score), msg])
    while cpt-anomalies_nb < 0:
        table_data.append([cpt+1,scores[cpt],explanations[cpt]])
        cpt+=1
    
    if anomalies_nb == 0:
        ok_sentence = Paragraph(f"Aucune anomalie détectée !", styles['BodyText'])
        story.append(ok_sentence)
        story.append(Spacer(1,12))
    else:
        table = Table(table_data)
        table.setStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ])
        story.append(table)
    
    
    doc.build(story)
    print(f"Rapport généré : {output_path}")

def get_explanation_for_score(score):
    if score <= 14:
        return "Un score de 0 à 14 indique que le fichier respecte les conventions standards."
    elif score <= 20:
        return "Un score de 15 à 20 signale des anomalies mineures..."
    elif score <= 45:
        return "Un score de 21 à 45 révèle plusieurs indicateurs suspects..."
    else:
        return "Un score de 46 ou plus suggère la présence de plusieurs anomalies graves."
