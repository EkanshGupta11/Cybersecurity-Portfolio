from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from jinja2 import Template

def generate_html_report(data, filename="report.html"):
    template = Template("""
    <html><body><h1>Security Audit Report</h1>
    <table border="1">
    <tr><th>Port</th><th>Status</th><th>Banner</th><th>Risk</th></tr>
    {% for item in data %}
    <tr><td>{{item.port}}</td><td>{{item.status}}</td><td>{{item.banner}}</td><td>{{item.risk}}</td></tr>
    {% endfor %}
    </table></body></html>
    """)
    with open(filename, 'w') as f:
        f.write(template.render(data=data))
    print(f"[*] HTML Report generated: {filename}")

def generate_pdf_report(data, filename="report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Security Audit Report")
    y = 700
    for item in data:
        c.drawString(100, y, f"Port: {item['port']} | Risk: {item['risk']}")
        y -= 20
    c.save()
    print(f"[*] PDF Report generated: {filename}")