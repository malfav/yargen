from flask import Flask, request, render_template_string
import yara
import pefile
import hashlib
import io
import os

app = Flask(__name__)

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>YARA Rule Generator</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 0;
        }
        header {
            background: #333;
            color: #d4d4d4;
            padding: 20px;
            border-bottom: 2px solid #444;
        }
        header h1 {
            margin: 0;
            font-size: 24px;
            text-align: center;
        }
        .container {
            width: 80%;
            margin: auto;
            overflow: hidden;
        }
        .card {
            background: #252525;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5);
        }
        .card h2 {
            color: #f39c12;
        }
        .card p, .card pre {
            color: #d4d4d4;
        }
        form {
            background: #333;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5);
        }
        form input[type="submit"] {
            background: #f39c12;
            border: none;
            padding: 10px;
            color: #fff;
            border-radius: 5px;
            cursor: pointer;
        }
        form input[type="submit"]:hover {
            background: #e67e22;
        }
        footer {
            background: #333;
            color: #d4d4d4;
            text-align: center;
            padding: 10px;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
        .icon {
            font-size: 24px;
            color: #f39c12;
            vertical-align: middle;
            margin-right: 10px;
        }
        .background-image {
            background: url('https://example.com/advanced-threat-intel-bg.jpg') no-repeat center center fixed;
            background-size: cover;
            position: absolute;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.5;
        }
        .upload-container {
            margin-top: 20px;
        }
        .upload-container input[type="file"] {
            background: #f39c12;
            border: none;
            padding: 10px;
            color: #fff;
            border-radius: 5px;
            cursor: pointer;
        }
        .upload-container input[type="file"]::file-selector-button {
            border: none;
            background: #f39c12;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="background-image"></div>
    <header>
        <div class="container">
            <h1><i class="fas fa-shield-alt icon"></i> YARA Rule Generator</h1>
        </div>
    </header>

    <div class="container">
        <div class="card">
            <form method="post" enctype="multipart/form-data">
                <h2>Upload a File</h2>
                <input type="file" name="file" accept=".exe,.dll,.pe,.txt,.pdf" required>
                <input type="submit" value="Generate YARA Rule">
            </form>
        </div>

        {% if yara_rule %}
        <div class="card">
            <h2>Generated YARA Rule</h2>
            <pre>{{ yara_rule }}</pre>
        </div>
        {% endif %}
    </div>

    <footer>
        <p>&copy; 2024 Threat Intelligence Labs. All rights reserved.</p>
    </footer>
</body>
</html>
'''

def hash_file(file_data):
    md5 = hashlib.md5(file_data).hexdigest()
    sha1 = hashlib.sha1(file_data).hexdigest()
    sha256 = hashlib.sha256(file_data).hexdigest()
    return {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256
    }

def generate_yara_rule(file_data, file_name):
    yara_rule = 'rule generated_rule {\n'
    
    hashes = hash_file(file_data)
    yara_rule += '    meta:\n'
    yara_rule += f'        description = "Generated rule for {file_name}"\n'
    yara_rule += f'        md5_hash = "{hashes["md5"]}"\n'
    yara_rule += f'        sha1_hash = "{hashes["sha1"]}"\n'
    yara_rule += f'        sha256_hash = "{hashes["sha256"]}"\n'
    
    try:
        if file_name.endswith(('.exe', '.dll', '.pe')):
            pe = pefile.PE(data=file_data)
            strings = []
            
            yara_rule += '    strings:\n'
            
            for section in pe.sections:
                try:
                    section_data = section.get_data()
                    for string in section_data.split(b'\x00'):
                        if len(string) > 4:
                            decoded_string = string.decode(errors='ignore')
                            yara_rule += f'        $s{len(strings)} = "{decoded_string}"\n'
                            strings.append(decoded_string)
                except:
                    pass

            yara_rule += '    condition:\n'
            yara_rule += '        all of them\n'
        elif file_name.endswith(('.txt', '.pdf')):
            file_data = file_data.decode(errors='ignore')
            yara_rule += '    strings:\n'
            yara_rule += f'        $text = /{re.escape(file_data[:200])}/\n'  # Regex for string matching
            yara_rule += '    condition:\n'
            yara_rule += '        $text\n'
        else:
            yara_rule += '    strings:\n'
            yara_rule += '        $file = "Unsupported file type"\n'
            yara_rule += '    condition:\n'
            yara_rule += '        $file\n'

    except Exception as e:
        yara_rule = f'Error generating YARA rule: {str(e)}'
    
    yara_rule += '}'
    return yara_rule

@app.route('/', methods=['GET', 'POST'])
def index():
    yara_rule = None
    
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_data = file.read()
            file_name = file.filename
            yara_rule = generate_yara_rule(file_data, file_name)
    
    return render_template_string(HTML_TEMPLATE, yara_rule=yara_rule)

if __name__ == '__main__':
    app.run(debug=True)
