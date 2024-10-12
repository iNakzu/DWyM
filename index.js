import express from 'express';
import { resolve } from 'path';
import { engine } from 'express-handlebars';
import { neon } from '@neondatabase/serverless';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const sql = neon('postgresql://neondb_owner:qkhcQGLeH57O@ep-plain-mountain-a5pdpm64.us-east-2.aws.neon.tech/neondb?sslmode=require');

const app = express(); 
const port = 3000;

app.use(express.static('static'));

// Middleware para analizar el cuerpo de las solicitudes POST
app.use(express.json());
app.use(express.urlencoded());

// Middleware para analizar las cookies
app.use(cookieParser());

// Configurar Handlebars como motor de plantillas
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

const JWT_SECRET = 'wt_secret_key';

// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).render('login', { error: 'Acceso denegado. Por favor, inicia sesión.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).render('login', { error: 'Token inválido. Por favor, inicia sesión de nuevo.' });
        }
        req.user = user;
        next();
    });
};


app.get('/', (req, res) => {
    res.render('index');
});

app.get('/admin', authenticateToken, (req, res) => {
    res.render('admin');
});

app.get('/cart', authenticateToken, (req, res) => {
    res.render('cart');
});

app.get('/profile', authenticateToken, async (req, res) => {
    try {
        // Obtener los datos del usuario desde la base de datos
        const result = await sql`
            SELECT name, email, wallet FROM users WHERE id = ${req.user.id}
        `;
        
        const user = result[0];

        if (user) {
            res.render('profile', {
                name: user.name,
                email: user.email,
                wallet: user.wallet
            });
        } else {
            res.status(404).render('profile', { error: 'Usuario no encontrado.' });
        }
    } catch (error) {
        console.error('Error al obtener los datos del usuario:', error);
        res.status(500).render('profile', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

// Ruta para mostrar el formulario de inicio de sesión
app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

// Ruta para manejar el envío del formulario de inicio de sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validar entrada
    if (!email || !password) {
        return res.status(400).render('login', { error: 'Todos los campos son obligatorios.' });
    }

    try {
        // Consultar la base de datos para obtener el usuario
        const result = await sql`
            SELECT * FROM users WHERE email = ${email}
        `;
        
        const user = result[0];

        if (user) {
            // Comparar la contraseña proporcionada con el hash almacenado
            const match = await bcrypt.compare(password, user.password);

            if (match) {
                // Generar un token JWT
                const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

                // Guardar el token en una cookie
                res.cookie('token', token, { httpOnly: true });
                
                console.log('Login successful:', user);
                res.redirect('/');
            } else {
                console.log('Login unsuccessful: Incorrect password');
                res.status(401).render('login', { error: 'Usuario o contraseña incorrectos' });
            }
        } else {
            console.log('Login unsuccessful: No user found');
            res.status(401).render('login', { error: 'Usuario o contraseña incorrectos' });
        }
    } catch (error) {
        console.error('Error al consultar la base de datos:', error);
        res.status(500).render('login', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

app.post('/signup', async (req, res) => {
    const { country, name, email, password } = req.body;

    const hash = bcrypt.hashSync(password, 10);

    // Validar entrada
    if (!country || !name || !email || !password) {
        return res.status(400).render('signup', { error: 'Todos los campos son obligatorios.' });
    }

    try {
        // Verificar si el email ya está registrado
        const existingUser = await sql`
            SELECT * FROM users WHERE email = ${email}
        `;

        if (existingUser.length > 0) {
            return res.status(400).render('signup', { error: 'El email ya está registrado.' });
        }

        // Insertar el nuevo usuario en la base de datos
        await sql`
            INSERT INTO users (country, name, email, password) VALUES (${country}, ${name}, ${email}, ${hash})
        `;

        console.log('User signup:', { country, name, email, password, hash});
        res.render('signup', { success: 'Usuario registrado exitosamente.' });
    }
    catch (error) {
        console.error('Error al registrar el usuario:', error);
        res.status(500).render('signup', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});