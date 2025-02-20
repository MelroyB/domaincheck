from flask import Flask, request, render_template
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
                spf_record = rdata.to_text().strip('"')
                return True, spf_record, parse_spf_record(spf_record)
        return False, "No SPF record found", []
    except dns.resolver.NoAnswer:
        return False, "No SPF record found", []
    except Exception as e:
        return False, str(e), []

def parse_spf_record(spf_record):
    mechanisms = []
    parts = spf_record.split()
    for part in parts:
        part = part.strip('"')
        if part.startswith('v=spf1'):
            mechanisms.append(('v', 'spf1', '', '', 'The SPF record version'))
        elif part.startswith(('include:', 'ip4:', 'ip6:')):
            prefix, value = part.split(':', 1)
            if prefix == 'include':
                description = "The specified domain is searched for an 'allow'."
            else:
                description = "IP addresses are allowed."
            mechanisms.append((prefix, prefix, value, 'Pass', description))
        elif part == '-all':
            mechanisms.append((part, '', '', 'Fail', 'Always matches. It goes at the end of your record.'))
        else:
            mechanisms.append((part, '', '', '', ''))
    return mechanisms

def check_dmarc(domain):
    try:
        dmarc_domain = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = answers[0].to_text().strip('"')
        return True, parse_dmarc_record(dmarc_record)
    except dns.resolver.NoAnswer:
        return False, "No DMARC record found"
    except Exception as e:
        return False, str(e)

def parse_dmarc_record(dmarc_record):
    tags = {}
    for tag in dmarc_record.split(';'):
        if '=' in tag:
            key, value = tag.strip().split('=', 1)
            tags[key] = value
    return tags

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        
        security_txt_status, security_txt_content = check_security_txt(domain)
        dkim_status, dkim_content = check_dkim(domain)
        spf_status, spf_raw, spf_content = check_spf(domain)
        dmarc_status, dmarc_content = check_dmarc(domain)

        results = {
            'security_txt': {'status': security_txt_status, 'content': security_txt_content},
            'dkim': {'status': dkim_status, 'content': dkim_content},
            'spf': {'status': spf_status, 'raw': spf_raw, 'content': spf_content},
            'dmarc': {'status': dmarc_status, 'content': dmarc_content},
        }
        
        return render_template('results.html', domain=domain, results=results)
    
    return render_template('index.html')

if __name__ == '__main__':

    app.run(host='0.0.0.0', debug=True)
