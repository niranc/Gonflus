const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        cb(null, true);
    }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    const files = fs.readdirSync(uploadDir).map(file => {
        const filePath = path.join(uploadDir, file);
        const stats = fs.statSync(filePath);
        return {
            name: file,
            size: stats.size,
            uploadDate: stats.mtime,
            ext: path.extname(file).toLowerCase()
        };
    }).sort((a, b) => b.uploadDate - a.uploadDate);
    
    res.render('index', { files });
});

app.post('/upload', upload.single('file'), (req, res) => {
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

app.get('/view/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    const ext = path.extname(filename).toLowerCase();
    const stats = fs.statSync(filePath);
    
    if (['.jpg', '.jpeg', '.png', '.gif', '.svg'].includes(ext)) {
        res.sendFile(filePath);
    } else if (ext === '.pdf') {
        res.contentType('application/pdf');
        res.sendFile(filePath);
    } else if (['.html', '.htm'].includes(ext)) {
        const content = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(content);
    } else if (ext === '.xml') {
        const content = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        res.send(content);
    } else if (['.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'].includes(ext)) {
        res.download(filePath);
    } else if (['.txt', '.csv', '.rtf'].includes(ext)) {
        const content = fs.readFileSync(filePath, 'utf8');
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.send(`<pre>${escapeHtml(content)}</pre>`);
    } else {
        res.download(filePath);
    }
});

app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    
    res.download(filePath);
});

app.delete('/delete/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    fs.unlinkSync(filePath);
    res.json({ success: true });
});

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

app.use((req, res) => {
    res.status(404).render('404');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('500', { error: err.message });
});

app.listen(PORT, () => {
    console.log(`[+] Upload test server running on http://localhost:${PORT}`);
    console.log(`[+] Upload directory: ${uploadDir}`);
});

