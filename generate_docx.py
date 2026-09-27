import markdown
from html2docx import html2docx
import os
import re

def convert_md_to_docx(md_path, docx_path, title):
    print(f"Converting {md_path} to {docx_path}...")
    with open(md_path, 'r', encoding='utf-8') as f:
        md_text = f.read()
    
    # Convert MD to HTML
    html_body = markdown.markdown(md_text, extensions=['tables', 'fenced_code', 'nl2br'])
    
    # Wrap in a neat HTML template without <style> blocks that html2docx chokes on
    html = f"""
    <html>
        <body>
            {html_body}
        </body>
    </html>
    """
    
    # Clean invalid XML control characters
    html = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', html)
    
    # Convert HTML to DOCX
    buf = html2docx(html, title=title)
    
    with open(docx_path, 'wb') as f:
        f.write(buf.getvalue())
    print(f"Successfully created {docx_path}")

if __name__ == "__main__":
    # Paths
    readme_md = r"d:\RootNode-Rebels\AWS Project\README.md"
    readme_docx = r"d:\RootNode-Rebels\AWS Project\docs\AWSSecurity_README.docx"
    
    deploy_md = r"C:\Users\LENOVO\.gemini\antigravity-ide\brain\22b310a5-d9e0-43d3-85d9-1d860b2c2a04\aws_deployment_guide.md"
    deploy_docx = r"d:\RootNode-Rebels\AWS Project\docs\AWS_Deployment_Guide.docx"
    
    # Ensure docs directory exists
    os.makedirs(r"d:\RootNode-Rebels\AWS Project\docs", exist_ok=True)
    
    # Convert
    convert_md_to_docx(readme_md, readme_docx, "AWSSecurity AI - Documentation")
    convert_md_to_docx(deploy_md, deploy_docx, "AWS Deployment Guide")

