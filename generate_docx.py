import markdown
from html2docx import html2docx
import os
import re
import logging

# [SECURITY V10: Enforce structured logging instead of print()]
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AWSSecurity_DocX_Generator")

def convert_md_to_docx(md_path, docx_path, title):
    logger.info(f"Initiating conversion: {md_path} -> {docx_path}")
    
    # [SECURITY V08: Explicit error handling for file operations]
    try:
        if not os.path.exists(md_path):
            raise FileNotFoundError(f"Source Markdown file not found at path: {md_path}")

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
            
        logger.info(f"SUCCESS: Successfully created {docx_path}")

    except PermissionError:
        logger.error(f"FAILED: Permission denied writing to {docx_path}. Ensure the file is not currently open in Microsoft Word.")
    except Exception as e:
        logger.error(f"CRITICAL ERROR: Failed to convert document '{title}' due to an unexpected error: {str(e)}")

if __name__ == "__main__":
    # Paths
    base_dir = os.path.abspath(os.path.dirname(__file__))
    readme_md = os.path.join(base_dir, "README.md")
    readme_docx = os.path.join(base_dir, "docs", "AWSSecurity_README.docx")
    
    # The deployment guide path remains external as configured
    deploy_md = r"C:\Users\LENOVO\.gemini\antigravity-ide\brain\22b310a5-d9e0-43d3-85d9-1d860b2c2a04\aws_deployment_guide.md"
    deploy_docx = os.path.join(base_dir, "docs", "AWS_Deployment_Guide.docx")
    
    # Ensure docs directory exists securely
    try:
        os.makedirs(os.path.join(base_dir, "docs"), exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create output directory: {str(e)}")
        exit(1)
    
    # Convert
    convert_md_to_docx(readme_md, readme_docx, "AWSSecurity AI - Documentation")
    convert_md_to_docx(deploy_md, deploy_docx, "AWS Deployment Guide")

