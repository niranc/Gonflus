const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const http = require('http');
const https = require('https');
const { parseString } = require('xml2js');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const uploadDirs = {
    php: path.join(__dirname, 'uploads', 'php'),
    asp: path.join(__dirname, 'uploads', 'asp'),
    java: path.join(__dirname, 'uploads', 'java')
};

Object.values(uploadDirs).forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

function createStorage(uploadDir) {
    return multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, uniqueSuffix + path.extname(file.originalname));
        }
    });
}

const uploads = {
    php: multer({
        storage: createStorage(uploadDirs.php),
        limits: { fileSize: 50 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            cb(null, true);
        }
    }),
    asp: multer({
        storage: createStorage(uploadDirs.asp),
        limits: { fileSize: 50 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            cb(null, true);
        }
    }),
    java: multer({
        storage: createStorage(uploadDirs.java),
        limits: { fileSize: 50 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            cb(null, true);
        }
    })
};

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.render('home');
});

function getFiles(uploadDir) {
    if (!fs.existsSync(uploadDir)) {
        return [];
    }
    return fs.readdirSync(uploadDir).map(file => {
        const filePath = path.join(uploadDir, file);
        const stats = fs.statSync(filePath);
        return {
            name: file,
            size: stats.size,
            uploadDate: stats.mtime,
            ext: path.extname(file).toLowerCase()
        };
    }).sort((a, b) => b.uploadDate - a.uploadDate);
}

function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function makeHttpRequest(url, callback) {
    try {
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            method: 'GET',
            timeout: 5000
        };

        const req = client.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                callback(null, { status: res.statusCode, data: data });
            });
        });

        req.on('error', (err) => {
            callback(err, null);
        });

        req.on('timeout', () => {
            req.destroy();
            callback(new Error('Request timeout'), null);
        });

        req.end();
    } catch (err) {
        callback(err, null);
    }
}

function parseXMLVulnerable(content, callback) {
    parseString(content, {
        explicitArray: false,
        mergeAttrs: true,
        explicitCharkey: false,
        ignoreAttrs: false,
        explicitRoot: true
    }, (err, result) => {
        if (err) {
            callback(err, null);
        } else {
            callback(null, result);
        }
    });
}

app.get('/php', (req, res) => {
    const files = getFiles(uploadDirs.php);
    res.render('php', { files });
});

app.post('/php/upload', uploads.php.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    res.json({
        success: true,
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
    });
});

app.get('/php/view/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.php, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    const ext = path.extname(filename).toLowerCase();
    const content = fs.readFileSync(filePath);
    
    if (['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
        res.sendFile(filePath);
    } else if (ext === '.svg') {
        const svgContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'image/svg+xml');
        res.send(svgContent);
    } else if (ext === '.pdf') {
        res.contentType('application/pdf');
        res.send(content);
    } else if (['.html', '.htm'].includes(ext)) {
        const htmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(htmlContent);
    } else if (ext === '.xml') {
        const xmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        
        if (xmlContent.includes('<!ENTITY') || xmlContent.includes('<!DOCTYPE')) {
            parseXMLVulnerable(xmlContent, (err, result) => {
                if (err) {
                    res.send(xmlContent);
                } else {
                    if (xmlContent.includes('http://') || xmlContent.includes('https://') || xmlContent.includes('file://')) {
                        const urlMatch = xmlContent.match(/(http[s]?:\/\/[^\s"']+|file:\/\/[^\s"']+)/i);
                        if (urlMatch) {
                            makeHttpRequest(urlMatch[0], (err, response) => {
                                if (!err && response) {
                                    res.send(`<!-- SSRF triggered: ${urlMatch[0]} -->\n${xmlContent}`);
                                } else {
                                    res.send(xmlContent);
                                }
                            });
                            return;
                        }
                    }
                    res.send(xmlContent);
                }
            });
        } else {
            res.send(xmlContent);
        }
    } else if (['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'].includes(ext)) {
        res.download(filePath);
    } else if (['.txt', '.csv', '.rtf'].includes(ext)) {
        const textContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        
        if (textContent.includes('|') || textContent.includes(';') || textContent.includes('`') || textContent.includes('$(')) {
            const commandMatch = textContent.match(/([|;`$\(].*)/);
            if (commandMatch) {
                exec(commandMatch[0], { timeout: 2000 }, (error, stdout, stderr) => {
                    res.send(`<pre>${escapeHtml(textContent)}</pre>\n<!-- RCE attempt: ${commandMatch[0]} -->`);
                });
                return;
            }
        }
        
        if (textContent.match(/https?:\/\/[^\s]+/)) {
            const urlMatch = textContent.match(/(https?:\/\/[^\s]+)/);
            if (urlMatch) {
                makeHttpRequest(urlMatch[0], () => {});
            }
        }
        
        res.send(`<pre>${escapeHtml(textContent)}</pre>`);
    } else if (ext === '.md' || ext === '.markdown') {
        const mdContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(mdContent);
    } else {
        res.download(filePath);
    }
});

app.get('/php/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.php, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    res.download(filePath);
});

app.delete('/php/delete/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.php, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    fs.unlinkSync(filePath);
    res.json({ success: true });
});

app.get('/asp', (req, res) => {
    const files = getFiles(uploadDirs.asp);
    res.render('asp', { files });
});

app.post('/asp/upload', uploads.asp.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    res.json({
        success: true,
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
    });
});

app.get('/asp/view/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.asp, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    const ext = path.extname(filename).toLowerCase();
    const content = fs.readFileSync(filePath);
    
    if (['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
        res.sendFile(filePath);
    } else if (ext === '.svg') {
        const svgContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'image/svg+xml');
        res.send(svgContent);
    } else if (ext === '.pdf') {
        res.contentType('application/pdf');
        res.send(content);
    } else if (['.html', '.htm'].includes(ext)) {
        const htmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(htmlContent);
    } else if (ext === '.xml') {
        const xmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        
        if (xmlContent.includes('<!ENTITY') || xmlContent.includes('<!DOCTYPE')) {
            parseXMLVulnerable(xmlContent, (err, result) => {
                if (err) {
                    res.send(xmlContent);
                } else {
                    if (xmlContent.includes('http://') || xmlContent.includes('https://') || xmlContent.includes('file://')) {
                        const urlMatch = xmlContent.match(/(http[s]?:\/\/[^\s"']+|file:\/\/[^\s"']+)/i);
                        if (urlMatch) {
                            makeHttpRequest(urlMatch[0], (err, response) => {
                                if (!err && response) {
                                    res.send(`<!-- SSRF triggered: ${urlMatch[0]} -->\n${xmlContent}`);
                                } else {
                                    res.send(xmlContent);
                                }
                            });
                            return;
                        }
                    }
                    res.send(xmlContent);
                }
            });
        } else {
            res.send(xmlContent);
        }
    } else if (['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'].includes(ext)) {
        res.download(filePath);
    } else if (['.txt', '.csv', '.rtf'].includes(ext)) {
        const textContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        
        if (textContent.includes('|') || textContent.includes(';') || textContent.includes('`') || textContent.includes('$(')) {
            const commandMatch = textContent.match(/([|;`$\(].*)/);
            if (commandMatch) {
                exec(commandMatch[0], { timeout: 2000 }, (error, stdout, stderr) => {
                    res.send(`<pre>${escapeHtml(textContent)}</pre>\n<!-- RCE attempt: ${commandMatch[0]} -->`);
                });
                return;
            }
        }
        
        if (textContent.match(/https?:\/\/[^\s]+/)) {
            const urlMatch = textContent.match(/(https?:\/\/[^\s]+)/);
            if (urlMatch) {
                makeHttpRequest(urlMatch[0], () => {});
            }
        }
        
        res.send(`<pre>${escapeHtml(textContent)}</pre>`);
    } else if (ext === '.md' || ext === '.markdown') {
        const mdContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(mdContent);
    } else {
        res.download(filePath);
    }
});

app.get('/asp/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.asp, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    res.download(filePath);
});

app.delete('/asp/delete/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.asp, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    fs.unlinkSync(filePath);
    res.json({ success: true });
});

app.get('/java', (req, res) => {
    const files = getFiles(uploadDirs.java);
    res.render('java', { files });
});

app.post('/java/upload', uploads.java.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    res.json({
        success: true,
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
    });
});

app.get('/java/view/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.java, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    const ext = path.extname(filename).toLowerCase();
    const content = fs.readFileSync(filePath);
    
    if (['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
        res.sendFile(filePath);
    } else if (ext === '.svg') {
        const svgContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'image/svg+xml');
        res.send(svgContent);
    } else if (ext === '.pdf') {
        res.contentType('application/pdf');
        res.send(content);
    } else if (['.html', '.htm'].includes(ext)) {
        const htmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(htmlContent);
    } else if (ext === '.xml') {
        const xmlContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        
        if (xmlContent.includes('<!ENTITY') || xmlContent.includes('<!DOCTYPE')) {
            parseXMLVulnerable(xmlContent, (err, result) => {
                if (err) {
                    res.send(xmlContent);
                } else {
                    if (xmlContent.includes('http://') || xmlContent.includes('https://') || xmlContent.includes('file://')) {
                        const urlMatch = xmlContent.match(/(http[s]?:\/\/[^\s"']+|file:\/\/[^\s"']+)/i);
                        if (urlMatch) {
                            makeHttpRequest(urlMatch[0], (err, response) => {
                                if (!err && response) {
                                    res.send(`<!-- SSRF triggered: ${urlMatch[0]} -->\n${xmlContent}`);
                                } else {
                                    res.send(xmlContent);
                                }
                            });
                            return;
                        }
                    }
                    res.send(xmlContent);
                }
            });
        } else {
            res.send(xmlContent);
        }
    } else if (['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'].includes(ext)) {
        res.download(filePath);
    } else if (['.txt', '.csv', '.rtf'].includes(ext)) {
        const textContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        
        if (textContent.includes('|') || textContent.includes(';') || textContent.includes('`') || textContent.includes('$(')) {
            const commandMatch = textContent.match(/([|;`$\(].*)/);
            if (commandMatch) {
                exec(commandMatch[0], { timeout: 2000 }, (error, stdout, stderr) => {
                    res.send(`<pre>${escapeHtml(textContent)}</pre>\n<!-- RCE attempt: ${commandMatch[0]} -->`);
                });
                return;
            }
        }
        
        if (textContent.match(/https?:\/\/[^\s]+/)) {
            const urlMatch = textContent.match(/(https?:\/\/[^\s]+)/);
            if (urlMatch) {
                makeHttpRequest(urlMatch[0], () => {});
            }
        }
        
        res.send(`<pre>${escapeHtml(textContent)}</pre>`);
    } else if (ext === '.md' || ext === '.markdown') {
        const mdContent = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(mdContent);
    } else {
        res.download(filePath);
    }
});

app.get('/java/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.java, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    res.download(filePath);
});

app.delete('/java/delete/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDirs.java, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    fs.unlinkSync(filePath);
    res.json({ success: true });
});

app.use((req, res) => {
    res.status(404).render('404');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('500', { error: err.message });
});

app.listen(PORT, () => {
    console.log(`[+] Upload test server running on http://localhost:${PORT}`);
    console.log(`[+] PHP upload directory: ${uploadDirs.php}`);
    console.log(`[+] ASP upload directory: ${uploadDirs.asp}`);
    console.log(`[+] Java upload directory: ${uploadDirs.java}`);
});
