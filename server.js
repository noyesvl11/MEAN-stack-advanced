const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const users = [
    { username: 'admin', password: bcrypt.hashSync('admin123', 10), role: 'admin' },
    { username: 'user', password: bcrypt.hashSync('user123', 10), role: 'user' }
];
const SECRET = 'secret key';

app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body;
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ msg: 'Пользователь уже зарегистрирован' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    users.push({ username, password: hashedPassword, role });
    res.json({ msg: 'Регистрация прошла успешно' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ msg: 'Неверное имя пользователя или пароль' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.get('/api/protected', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ msg: 'Токен не предоставлен' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET);
        res.json({ msg: 'Доступ разрешён', user: decoded });
    } catch (err) {
        res.status(403).json({ msg: 'Токен недействителен или истёк' });
    }
});

// Контроль доступа на основе роли для администраторов
app.get('/admin', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ msg: 'Токен не предоставлен' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ msg: 'Доступ только для администраторов' });
        }
        res.json({ msg: 'Доступ для администратора разрешён' });
    } catch (err) {
        res.status(403).json({ msg: 'Токен недействителен или истёк' });
    }
});

// Отдача статических файлов
app.use(express.static(path.join(__dirname, 'auth-frontend/dist/auth-frontend/browser')));

app.get('/*', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth-frontend/dist/auth-frontend/browser', 'index.html'));
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Что-то пошло не так!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
