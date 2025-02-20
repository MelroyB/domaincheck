from flask import Flask, request, render_template, jsonify
import dns.resolver
import requests

app = Flask(__name__)

def check_security_txt(domain):
    try:
        response = requests.get(f'https://{domain}/.well-known/security.txt', timeout=5)
        if response.status_code == 200 and 'text/plain' in response.headers.get('Content-Type', ''):
            return True, response.text
        else:
            return False, "Security.txt not found or the response is not in plain text"
    except requests.RequestException:
        return False, "Unable to retrieve security.txt"

def check_dkim(domain):
    try:
        answers = dns.resolver.resolve(f'dkim._domainkey.{domain}', 'TXT')
        return True, [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        return False, "No DKIM record found"
    except Exception as e:
        return False, str(e)

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                return True, rdata.to_text()
        return False, "No SPF record found"
    except dns.resolver.NoAnswer:
        return False, "No SPF record found"
    except Exception as e:
        return False, str(e)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        
        security_txt_status, security_txt_content = check_security_txt(domain)
        dkim_status, dkim_content = check_dkim(domain)
        spf_status, spf_content = check_spf(domain)
        
        results = {
            'security_txt': {'status': security_txt_status, 'content': security_txt_content},
            'dkim': {'status': dkim_status, 'content': dkim_content},
            'spf': {'status': spf_status, 'content': spf_content},
        }
        
        return render_template('results.html', domain=domain, results=results)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
