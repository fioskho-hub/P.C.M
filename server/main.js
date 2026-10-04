require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const fs = require('fs');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true, 
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

app.use(express.static(path.join(__dirname, '../public')));

const USERS_FILE = path.join(__dirname, 'data/users.json');

function readUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        return [];
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    try {
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

function saveUsers(users) {
    const dir = path.dirname(USERS_FILE);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}


// --- ROUTES API ---

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Nom d'utilisateur et mot de passe requis." });
        }

        const users = readUsers();

        const existingUser = users.find(u => u.username === username);
        if (existingUser) {
            return res.status(400).json({ error: "Ce nom d'utilisateur est déjà pris." });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = {
            id: Date.now().toString(),
            username,
            password: hashedPassword 
        };

        users.push(newUser);
        saveUsers(users);

        return res.status(201).json({ message: "Compte créé avec succès !", userId: newUser.id });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
    }
});


app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const users = readUsers();
        const user = users.find(u => u.username === username);

        if (!user) {
            return res.status(400).json({ error: "Utilisateur ou mot de passe incorrect." });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: "Utilisateur ou mot de passe incorrect." });
        }

        req.session.userId = user.id;
        req.session.username = user.username;

        return res.status(200).json({ message: "Connexion réussie !", username: user.username });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Erreur serveur lors de la connexion." });
    }
});


app.listen(PORT, () => {
    console.log(`Serveur lancé sur le port ${PORT}`);
});