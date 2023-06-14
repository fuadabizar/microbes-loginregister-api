const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// Konfigurasi koneksi database
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'microbe-db',
});

// Membuat koneksi ke database
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});

// API endpoint untuk registrasi
app.post('/register', (req, res) => {
  const { fullName, email, password } = req.body;
  
  // Menggunakan bcrypt untuk mengenkripsi password sebelum disimpan ke database
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error hashing password:', err);
      res.status(500).json({ error: 'Internal server error' });
    } else {
      const newUser = {
        fullName,
        email,
        password: hashedPassword,
      };
      
      // Menyimpan data pengguna baru ke database
      db.query('INSERT INTO users SET ?', newUser, (err, result) => {
        if (err) {
          console.error('Error inserting user into database:', err);
          res.status(500).json({ error: 'Internal server error' });
        } else {
          res.status(201).json({ message: 'User registered successfully' });
        }
      });
    }
  });
});

// API endpoint untuk login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Mengecek apakah email ada di database
  db.query('SELECT * FROM users WHERE email = ?', email, (err, results) => {
    if (err) {
      console.error('Error fetching user from database:', err);
      res.status(500).json({ error: 'Internal server error' });
    } else {
      if (results.length === 0) {
        res.status(401).json({ error: 'Invalid email or password' });
      } else {
        const user = results[0];

        // Membandingkan password yang diberikan dengan password di database menggunakan bcrypt
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
            console.error('Error comparing passwords:', err);
            res.status(500).json({ error: 'Internal server error' });
          } else {
            if (isMatch) {
              res.status(200).json({ message: 'Login successful' });
            } else {
              res.status(401).json({ error: 'Invalid email or password' });
            }
          }
        });
      }
    }
  });
});

// Menjalankan server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});