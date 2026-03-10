const express = require('express');
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const validator = require("validator");
const db = require('./db');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const secret = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

//register

app.post('/register', (req,res) => {
  const {name,email,phone,password,confirm} = req.body;

  if(!name || !email || !phone || !password || !confirm) {
    return res.status(400).json({ error: "All fields are required"});
  }
  if(!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid email"});
  }
  if(!validator.isMobilePhone(phone, "any")) {
    return res.status(400).json({ error: "Invalid phone number"});
  }
  if(!validator.isStrongPassword(password)) {
    return res.status(400).json({ error: "Password must contain uppercase, lowercase, number and symbol"});
  }
  if(password !== confirm) {
    return res.status(400).json({ error: "Password not matching"});
  }

  db.query('select * from users where email=? OR phone=?',[email,phone], async (err,results) =>{
    if(err) {
      return res.status(500).json({ error: "Database error"});
    }
    if(results.length > 0) {
      return res.status(400).json({ error: "The user with this email or phone already exist"});
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const sql = 'insert into users(name,email,phone,password_hash) values(?,?,?,?)';
    db.query(sql,[name,email,phone,hashedPassword], (err, result) => {
      if(err) {
        return res.status(500).json({error: "Database error"});
      }

      const token = jwt.sign({id: result.insertId, name, email, phone}, secret, { expiresIn: "30d"});

      const user = {id: result.insertId, name, email, phone};

      res.status(201).json({
        message: "user created",
        token,
        user: user
      })

    });
  });
});

//login

app.post('/login', (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: "All fields required" });
  }

  let query;
  let value;

  if (validator.isEmail(identifier)) {
    query = 'SELECT * FROM users WHERE email = ?';
    value = identifier;
  } else if (validator.isMobilePhone(identifier, "any")) {
    query = 'SELECT * FROM users WHERE phone = ?';
    value = identifier;
  } else {
    return res.status(400).json({ error: "Invalid Email or Phone number" });
  }

  db.query(query, [value], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });

    const user = results[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      secret,
      { expiresIn: '30d' }
    );

    return res.status(200).json({
      message: "Login successful",
      token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  });
});


app.listen(PORT, () => {
  console.log(`The api is running on localhost:${PORT}`);
});
