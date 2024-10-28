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
app.use(express.urlencoded({ extended: true }));

// Middleware para analizar las cookies
app.use(cookieParser());

app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

const JWT_SECRET = 'jwt_secret_key';

// Middleware para verificar token JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        // return res.render('login', { error: 'Acceso denegado. Por favor, inicia sesión.' });
        return res.redirect('/login?error=Acceso denegado. Por favor, inicia sesión.');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect('/login?error=Inicia sesión de nuevo.');
        }
        req.user = user;
        next();
    });
};

// Middleware para verificar si el user es admininstrador
const checkAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.render('login', { error: 'Acceso denegado. Solo los administradores pueden acceder a esta página.' });
    }
    next();
};

// Middleware para redirigir si el usuario ya está autenticado
const redirectIfAuthenticated = (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return next();
            }
            return res.redirect('/?message=Ya has iniciado sesión');
        });
    } else {
        next();
    }
};

app.get('/', async (req, res) => {
    const message = req.query.message;
    
    try {
        const result = await sql`
            SELECT id, img, title, price FROM products
        `;
        const products = result;
        res.render('index', { message, products });
    } catch (error) {
        console.error('Error al obtener los productos:', error);
        res.send('Error al obtener los productos');
    }
});

app.get('/admin', authenticateToken, checkAdmin, async (req, res) => {
    try {
        // Obtener el monto total de ventas desde la base de datos
        const salesResult = await sql`
            SELECT SUM(amount) FROM receipts
        `;

        let totalSales = salesResult[0].sum || 0;

        // Redondear el monto total de ventas a 2 decimales
        totalSales = parseFloat(totalSales).toFixed(2);

        // Obtener los productos para la vista de administración
        const productsResult = await sql`
            SELECT id, title, price, stock FROM products
        `;
        const products = productsResult;

        // Renderizar la vista de administración con el monto total de ventas
        res.render('admin', { products, totalSales });
    } catch (error) {
        console.error('Error al obtener los productos:', error);
        res.send('Error al obtener los productos');
    }
});

app.get('/edit-product/:id', authenticateToken, checkAdmin, async (req, res) => {
    const productId = req.params.id;
    try {
        const result = await sql`
            SELECT id, img, title, price, stock FROM products WHERE id = ${productId}
        `;
        const product = result[0];
        res.render('edit-product', { product });
    } catch (error) {
        console.error('Error al obtener el producto:', error);
        res.send('Error al obtener el producto');
    }
});

app.get('/create-product', authenticateToken, checkAdmin, (req, res) => {
    res.render('create-product');
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
            res.render('profile', { error: 'Usuario no encontrado.' });
        }
    } catch (error) {
        console.error('Error al obtener los datos del usuario:', error);
        res.render('profile', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

// Ruta para mostrar el formulario de inicio de sesión
app.get('/login', redirectIfAuthenticated, (req, res) => {
    const error = req.query.error;
    res.render('login', { error });
});

app.get('/signup', redirectIfAuthenticated, (req, res) => {
    res.render('signup');
});

app.get('/cart', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // Obtener los productos del carrito desde la base de datos
        const cartItems = await sql`
            SELECT p.id, p.title, p.price, c.quantity
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ${userId}
        `;

        const result = await sql`
            SELECT wallet FROM users WHERE id = ${userId}
        `;

        const user = result[0];

        // Calcular el total de cada producto y el total general
        cartItems.forEach(item => {
            item.total = (item.price * item.quantity).toFixed(2);
        });
        const total = cartItems.reduce((sum, item) => sum + parseFloat(item.total), 0).toFixed(2);

        res.render('cart', { cart: cartItems, wallet: user.wallet, total });
    } catch (error) {
        console.error('Error al obtener los productos del carrito:', error);
        res.send('Error al obtener los productos del carrito');
    }
});

app.post('/create-product', authenticateToken, async (req, res) => {
    const { img, title, price, stock } = req.body;
    try {
        await sql`
            INSERT INTO products (img, title, price, stock) VALUES (${img}, ${title}, ${price}, ${stock})
        `;
        res.redirect('/admin');
    } catch (error) {
        console.error('Error al crear el producto:', error);
        res.send('Error al crear el producto');
    }
});

app.post('/edit-product/:id', authenticateToken, async (req, res) => {
    const productId = req.params.id;
    const { img, title, price, stock } = req.body;
    try {
        await sql`
            UPDATE products SET img = ${img}, title = ${title}, price = ${price}, stock = ${stock} WHERE id = ${productId}
        `;
        res.redirect('/admin');
    } catch (error) {
        console.error('Error al actualizar el producto:', error);
        res.send('Error al actualizar el producto');
    }
});

app.post('/edit-product/:id', authenticateToken, async (req, res) => {
    const productId = req.params.id;
    const { img, title, price } = req.body;
    try {
        await sql`
            UPDATE products SET img = ${img}, title = ${title}, price = ${price} WHERE id = ${productId}
        `;
        res.redirect('/admin');
    } catch (error) {
        console.error('Error al actualizar el producto:', error);
        res.send('Error al actualizar el producto');
    }
});

app.post('/purchase', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // Obtener el total del carrito
        const cartItems = await sql`
            SELECT p.price, c.quantity FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ${userId}
        `;
        const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);

        // Obtener el saldo de la wallet del usuario
        const result = await sql`
            SELECT wallet FROM users WHERE id = ${userId}
        `;
        const user = result[0];

        if (parseFloat(user.wallet) < parseFloat(total)) {
            return res.render('index', { message: 'Fondos insuficientes en la wallet' });
        }

        // Descontar el total de la wallet del usuario
        await sql`
            UPDATE users SET wallet = wallet - ${total} WHERE id = ${userId}
        `;

        // Generar un recibo en la base de datos en tabla receipts
        await sql`
            INSERT INTO receipts (user_id, amount) VALUES (${userId}, ${total})
        `;

        // Vaciar el carrito del usuario
        await sql`
            DELETE FROM cart WHERE user_id = ${userId}
        `;

        res.render('index', { message: 'Compra realizada con éxito' });
    } catch (error) {
        console.error('Error al realizar la compra:', error);
        res.send('Error al realizar la compra');
    }
});

// Ruta para manejar el envío del formulario de inicio de sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validar entrada
    if (!email || !password) {
        return res.render('login', { error: 'Todos los campos son obligatorios.' });
    }

    try {
        // Consultar la base de datos para obtener el usuario
        const result = await sql`
            SELECT id, email, password FROM users WHERE email = ${email}
        `;
        
        const user = result[0];

        if (user) {
            // Comparar la contraseña proporcionada con el hash almacenado
            const match = await bcrypt.compare(password, user.password);

            if (match) {
                // Generar un token JWT que expire en 5 minutos
                const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '15m' });

                // Guardar el token en una cookie
                res.cookie('token', token, { httpOnly: true });
                
                // Imprimir solo el id y el email del usuario en la consola
                console.log('Login successful:', { id: user.id, email: user.email });
                
                res.redirect('/');
            } else {
                console.log('Login unsuccessful: Incorrect password');
                res.render('login', { error: 'Usuario o contraseña incorrectos' });
            }
        } else {
            console.log('Login unsuccessful: No user found');
            res.render('login', { error: 'Usuario o contraseña incorrectos' });
        }
    } catch (error) {
        console.error('Error al consultar la base de datos:', error);
        res.render('login', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

app.post('/signup', async (req, res) => {
    const { country, name, email, password, role } = req.body;

    const hash = bcrypt.hashSync(password, 10);

    // Validar entrada
    if (!country || !name || !email || !password) {
        return res.render('signup', { error: 'Todos los campos son obligatorios.' });
    }

    try {
        // Verificar si el email ya está registrado
        const existingUser = await sql`
            SELECT * FROM users WHERE email = ${email}
        `;

        if (existingUser.length > 0) {
            return res.render('signup', { error: 'El email ya está registrado.' });
        }

        // Insertar el nuevo usuario en la base de datos
        const result = await sql`
            INSERT INTO users (country, name, email, password, role) VALUES (${country}, ${name}, ${email}, ${hash}, ${role})
            RETURNING id, email, password, role
        `;

        const user = result[0];

        // Generar el token
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '15m' });;

        // Guardarlo en una cookie
        res.cookie('token', token, { httpOnly: true });

        console.log('User signup and login successful:', user);
        res.redirect('/');
    } catch (error) {
        console.error('Error al registrar el usuario:', error);
        res.render('signup', { error: 'Ocurrió un error en el servidor. Por favor, inténtalo de nuevo más tarde.' });
    }
});

app.post('/add-to-cart', authenticateToken, async (req, res) => {
    const { productId } = req.body;
    const userId = req.user.id;

    try {
        // Verificar si el producto ya está en el carrito del usuario
        const cartItem = await sql`
            SELECT * FROM cart WHERE user_id = ${userId} AND product_id = ${productId}
        `;

        if (cartItem.length > 0) {
            // Si el producto ya está en el carrito, incrementar la cantidad
            await sql`
                UPDATE cart SET quantity = quantity + 1 WHERE user_id = ${userId} AND product_id = ${productId}
            `;
        } else {
            // Si el producto no está en el carrito, agregarlo con una cantidad inicial de 1
            await sql`
                INSERT INTO cart (user_id, product_id, quantity) VALUES (${userId}, ${productId}, 1)
            `;
        }

        // Redirigir al usuario a la vista del carrito
        res.redirect('/cart');
    } catch (error) {
        // Manejar errores y enviar una respuesta de error
        console.error('Error al agregar el producto al carrito:', error);
        res.send('Error al agregar el producto al carrito');
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});