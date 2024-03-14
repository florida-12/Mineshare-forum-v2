const dotenv = require('dotenv');
const express = require('express');
const https = require('https');
const path = require('path');
const pg = require('pg');
const fs = require('fs/promises');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Recaptcha = require('express-recaptcha').RecaptchaV2;
const session = require('express-session');
const flash = require('express-flash');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const pgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const bcrypt = require('bcrypt');
const axios = require('axios');
const moment = require('moment-timezone');
const app = express();


dotenv.config();


app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'assets')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const recaptcha = new Recaptcha(process.env.RECAPTCHA_SITE_KEY, process.env.RECAPTCHA_SECRET_KEY);

const pool = new pg.Pool({
    user: process.env.DATABASE_USER,
    host: 'mineshare.top',
    database: 'mineshare_v2',
    password: process.env.DATABASE_PASSWORD,
    port: 5432,
});

const poolConfigOpts = {
    user: process.env.DATABASE_USER,
    host: 'mineshare.top',
    database: 'mineshare_v2',
    password: process.env.DATABASE_PASSWORD,
    port: 5432
}
const poolInstance = new pg.Pool(poolConfigOpts);
const postgreStore = new pgSession({
    pool: poolInstance,
    createTableIfMissing: true,
})

app.use(session({
    store: postgreStore,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 },
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());


let footer_html;

fs.readFile(path.join(__dirname, 'views/footer.ejs'), 'utf-8')
    .then(content => {
        footer_html = content;
    })
    .catch(error => {
        console.error('Error reading file:', error);
        process.exit(1);
    }
    );

async function generatePassword() {
    const minLength = 8;
    const maxLength = 20;
    const passwordLength = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;

    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?";

    let password = "";
    for (let i = 0; i < passwordLength; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset.charAt(randomIndex);
    }
    console.log(password);
    const hashedPassword = await bcrypt.hash(password, 10);
    return hashedPassword;
}

async function updateOnlineStatus(email) {
    const logdate = await pool.query('UPDATE users SET logdate = CURRENT_TIMESTAMP WHERE email = $1', [email]);
}

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
}, async (email, password, done) => {
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];

            if (!user.confirmation) {
                return done(null, false, { message: 'Email not confirmed. Please check your email for confirmation instructions.' });
            }

            const match = await bcrypt.compare(password, user.password);

            if (match) {
                const logdate = await pool.query('UPDATE users SET logdate = CURRENT_TIMESTAMP WHERE email = $1', [email]);
                return done(null, user);
            } else {
                return done(null, false, { message: 'Incorrect password.' });
            }
        } else {
            return done(null, false, { message: 'User not found.' });
        }
    } catch (error) {
        return done(error, null);
    }
}));


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: '/auth/google/callback',
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);

            if (userResult.rows.length > 0) {
                return done(null, userResult.rows[0]);
            } else {
                const password = await generatePassword();   //random password

                const newUserResult = await pool.query('INSERT INTO users (email, password, confirmation, regip) VALUES ($1, $2, $3, $4) RETURNING *', [profile.emails[0].value, password, true, 'GOOGLE']);

                return done(null, newUserResult.rows[0]);
            }
        } catch (error) {
            return done(error, null);
        }
    }));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const userQuery = 'SELECT * FROM users WHERE id = $1';
        const userResult = await pool.query(userQuery, [id]);

        if (userResult.rows.length > 0) {
            done(null, userResult.rows[0]);
        } else {
            done(null, false);
        }
    } catch (error) {
        done(error, null);
    }
});

app.post('/register', recaptcha.middleware.verify, async (req, res) => {
    if (req.recaptcha.error) {
        return res.send('Проверка reCaptcha не удалась');
    }

    const { email, password, password_repeat } = req.body;

    if (password != password_repeat) return res.status(400).json({ message: 'Password mismatch.' });

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userResult.rows.length > 0) {
            res.status(400).json({ message: 'Пользователь уже существует.' });
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);

            let regip = req.headers['x-forwarded-for'];
            if (regip == undefined) regip = '0.0.0.0';

            const confirmationToken = uuidv4();

            const newUserResult = await pool.query('INSERT INTO users (email, password, regip, confirmation_token) VALUES ($1, $2, $3, $4) RETURNING *', [email, hashedPassword, regip, confirmationToken]);

            const confirmationLink = `https://mineshare.top/account/confirm/${confirmationToken}`;
            sendConfirmationEmail(email, confirmationLink);

            res.redirect('/?login=confirmation')
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Роуты для аутентификации
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
    failureFlash: true,
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { successRedirect: '/', failureRedirect: '/' }));

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

app.get('/account', isAuthenticated, (req, res) => {
    if (!req.path.endsWith('/') && req.path !== '/') return res.redirect(301, req.path + '/');

    pool.query(`SELECT * FROM forum_teams WHERE owner = $1;`, [req.user.id], async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        const admin_teams = await pool.query('SELECT * FROM forum_teams;');

        updateOnlineStatus(req.user.email);

        res.render('account', { user: req.user, teams: result.rows, admin_teams: admin_teams.rows });
    });
});

app.post('/account/username', isAuthenticated, (req, res) => {
    const { username } = req.body;

    pool.query(`UPDATE users SET username = $1 WHERE id = $2;`, [username, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.post('/account/skin', isAuthenticated, (req, res) => {
    let { skin } = req.body;
    skin = skin.replace('-', '');

    pool.query(`UPDATE users SET skin = $1 WHERE id = $2;`, [skin, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.get('/account/:topic/:id/up', isAuthenticated, (req, res) => {
    const topic = req.params.topic;
    const id = req.params.id;

    pool.query(`UPDATE forum_${topic} SET update = CURRENT_TIMESTAMP WHERE identifier = $1 AND owner = $2;`, [id, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.get('/account/:topic/:id/open', isAuthenticated, (req, res) => {
    const topic = req.params.topic;
    const id = req.params.id;

    pool.query(`UPDATE forum_${topic} SET status = false WHERE identifier = $1 AND owner = $2;`, [id, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.get('/account/:topic/:id/close', isAuthenticated, (req, res) => {
    const topic = req.params.topic;
    const id = req.params.id;

    pool.query(`UPDATE forum_${topic} SET status = true WHERE identifier = $1 AND owner = $2;`, [id, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.get('/account/:topic/:id/edit', isAuthenticated, (req, res) => {
    const topic = req.params.topic;
    const id = req.params.id;

    pool.query(`SELECT * FROM forum_${topic} WHERE identifier = $1 AND owner = $2;`, [id, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.render('edit-topic-teams', { topics: result.rows });
    });
});

app.post('/account/:topic/:id/edit', isAuthenticated, (req, res) => {
    const topic = req.params.topic;
    const id = req.params.id;
    let { type, title, version, description, contacts } = req.body;

    const filteredContacts = contacts.filter(contact => {
        for (const key in contact) {
            if (contact.hasOwnProperty(key) && contact[key] !== null && contact[key] !== '') {
                return true;
            }
        }
        return false;
    });
    const contact = JSON.stringify(filteredContacts);

    pool.query(`UPDATE forum_${topic} SET type = $1, title = $2, description = $3, contact = $4, version = $5 WHERE owner = $6 AND identifier = $7;`, [type, title, description, contact, version, req.user.id, id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/account');
    });
});

app.get('/account/confirm/:token', async (req, res) => {
    const token = req.params.token;
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE confirmation_token = $1', [token]);

        if (userResult.rows.length > 0) {
            await pool.query('UPDATE users SET confirmation = true, confirmation_token = null WHERE id = $1', [userResult.rows[0].id]);
            res.redirect('/?login=confirmed');
        } else {
            res.status(400).json({ message: 'Неверный токен или пользователь не найден.' });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

function pluralize(number, one, few, many) {
    if (number === 1) {
        return one;
    } else if (number >= 2 && number <= 4) {
        return few;
    } else {
        return many;
    }
}

app.get('/', (req, res) => {
    pool.query(`SELECT username, skin, moder, admin, logdate FROM users WHERE admin = true OR moder = true ORDER BY admin DESC;`, async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        result.rows.forEach(row => {
            const yourDateTime = new Date(row.logdate);
            yourDateTime.setHours(yourDateTime.getHours() - 2);

            const currentDateTime = new Date();

            const differenceInMilliseconds = yourDateTime - currentDateTime;

            const diffInMinutes = Math.abs(Math.floor(differenceInMilliseconds / (1000 * 60)));
            row.online_minutes = diffInMinutes;

            if (diffInMinutes < 60) {
                row.last_online = `${diffInMinutes} ${pluralize(diffInMinutes, 'минуту', 'минуты', 'минут')} назад`;
            } else {
                const diffInHours = Math.floor(diffInMinutes / 60);
                row.last_online = `${diffInHours} ${pluralize(diffInHours, 'час', 'часа', 'часов')} назад`;
            }
        });

        const teams = await pool.query('SELECT id FROM forum_teams WHERE ban = false;');

        if (req.user) updateOnlineStatus(req.user.email);

        res.render('home', { user: req.user, moderators: result.rows, teams: teams.rows.length, footer: footer_html });
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/teams', (req, res) => {
    if (!req.path.endsWith('/') && req.path !== '/') return res.redirect(301, req.path + '/');

    pool.query(`SELECT forum_teams.*, users.username, users.skin, users.logdate FROM forum_teams JOIN users ON forum_teams.owner = users.id WHERE forum_teams.ban = false ORDER BY update DESC;`, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        result.rows.forEach(row => {
            const yourDateTime = new Date(row.logdate);
            yourDateTime.setHours(yourDateTime.getHours() - 2);

            const currentDateTime = new Date();

            const differenceInMilliseconds = yourDateTime - currentDateTime;

            const diffInMinutes = Math.abs(Math.floor(differenceInMilliseconds / (1000 * 60)));

            if (diffInMinutes < 60) {
                row.lastOnline = `${diffInMinutes} ${pluralize(diffInMinutes, 'минуту', 'минуты', 'минут')} назад`;
            } else {
                const diffInHours = Math.floor(diffInMinutes / 60);
                row.lastOnline = `${diffInHours} ${pluralize(diffInHours, 'час', 'часа', 'часов')} назад`;
            }
        });

        result.rows.forEach(row => {
            const yourDateTime = new Date(row.update);
            yourDateTime.setHours(yourDateTime.getHours() - 2);

            const currentDateTime = new Date();

            const differenceInMilliseconds = yourDateTime - currentDateTime;

            const diffInMinutes = Math.abs(Math.floor(differenceInMilliseconds / (1000 * 60)));

            if (diffInMinutes < 60) {
                row.update = `${diffInMinutes} ${pluralize(diffInMinutes, 'минуту', 'минуты', 'минут')} назад`;
            } else {
                const diffInHours = Math.floor(diffInMinutes / 60);
                row.update = `${diffInHours} ${pluralize(diffInHours, 'час', 'часа', 'часов')} назад`;
            }
        });

        if (req.user) updateOnlineStatus(req.user.email);

        res.render('teams', { user: req.user, topics: result.rows, footer: footer_html });
    });
});

app.get('/teams/topic/:id', (req, res) => {
    if (!req.path.endsWith('/') && req.path !== '/') return res.redirect(301, req.path + '/');

    pool.query(`SELECT forum_teams.*, users.username, users.skin FROM forum_teams JOIN users ON forum_teams.owner = users.id WHERE identifier = $1 LIMIT 1;`, [req.params.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        result.rows.forEach(row => {
            const pattern = /\['(.*?)'\]/;
            row.description = row.description.replace(pattern, '<img class="image" src="$1">');
        });

        res.render('topic-teams', { user: req.user, topics: result.rows, footer: footer_html });
    });
});

app.get('/teams/add', isAuthenticated, (req, res) => {
    res.render('create-topic-teams', { footer: footer_html });
});

app.post('/teams/add', isAuthenticated, (req, res) => {
    let { type, title, version, description, contacts } = req.body;
    const identifier = uuidv4();

    const filteredContacts = contacts.filter(contact => {
        for (const key in contact) {
            if (contact.hasOwnProperty(key) && contact[key] !== null && contact[key] !== '') {
                return true;
            }
        }
        return false;
    });
    const contact = JSON.stringify(filteredContacts);

    pool.query(`INSERT INTO forum_teams (identifier, type, title, description, contact, version, owner) VALUES ($1, $2, $3, $4, $5, $6, $7);`, [identifier, type, title, description, contact, version, req.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/teams');
    });
});

app.get('/manuals', (req, res) => {
    if (!req.path.endsWith('/') && req.path !== '/') return res.redirect(301, req.path + '/');

    pool.query(`SELECT forum_manuals.*, users.username, users.skin, users.logdate FROM forum_manuals JOIN users ON forum_manuals.owner = users.id WHERE forum_manuals.status = false AND forum_manuals.ban = false ORDER BY update DESC;`, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        result.rows.forEach(row => {
            row.update = moment.tz(row.update, 'Europe/Moscow').locale('ru').format('D MMM HH:mm');

            const yourDateTime = new Date(row.logdate);
            yourDateTime.setHours(yourDateTime.getHours() - 2);

            const currentDateTime = new Date();

            const differenceInMilliseconds = yourDateTime - currentDateTime;

            const diffInMinutes = Math.abs(Math.floor(differenceInMilliseconds / (1000 * 60)));

            if (diffInMinutes < 60) {
                row.lastOnline = `${diffInMinutes} ${pluralize(diffInMinutes, 'минуту', 'минуты', 'минут')} назад`;
            } else {
                const diffInHours = Math.floor(diffInMinutes / 60);
                row.lastOnline = `${diffInHours} ${pluralize(diffInHours, 'час', 'часа', 'часов')} назад`;
            }
        });

        if (req.user) updateOnlineStatus(req.user.email);

        res.render('manuals', { user: req.user, topics: result.rows, footer: footer_html });
    });
});

app.get('/manuals/add', isAuthenticated, (req, res) => {
    res.render('create-topic-manuals', { footer: footer_html });
});

async function sendConfirmationEmail(email, confirmationLink) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'mineshare.project@gmail.com',
            pass: process.env.EMAIL_SECRET
        }
    });

    const mailOptions = {
        from: 'mineshare.project@gmail.com',
        to: email,
        subject: 'Подтверждение регистрации',
        text: `Для подтверждения регистрации перейдите по ссылке: ${confirmationLink}`,
        html: `<p>Для подтверждения регистрации перейдите по ссылке: <a href="${confirmationLink}">${confirmationLink}</a></p>`,
    };

    await transporter.sendMail(mailOptions);
}

async function startServer() {
    try {
        // Загрузка закрытого ключа и сертификата
        const privateKey = await fs.readFile('config/private.key', 'utf8');
        const certificate = await fs.readFile('config/certificate.crt', 'utf8');

        const credentials = { key: privateKey, cert: certificate };

        // Создание HTTPS-сервера
        const httpsServer = https.createServer(credentials, app);

        // Прослушивание порта
        httpsServer.listen(443, () => {
            console.log(`\n--------------- RUNNING ---------------`);
            console.log(`${new Date()}`);
            console.log(`---------------------------------------\n`);
        });
    } catch (err) {
        console.error('Ошибка при чтении файлов:', err);
    }
}

startServer();