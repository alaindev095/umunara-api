app.post('/login', (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ Error: "All fields required" });
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
    return res.status(400).json({ Error: "Invalid Email or Phone number" });
  }

  db.query(query, [value], async (err, results) => {
    if (err) return res.status(500).json({ Error: "Database error" });
    if (results.length === 0) return res.status(404).json({ Error: "User not found" });

    const user = results[0];

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ Error: "Incorrect password" });

    // Create token
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      secret,
      { expiresIn: '30d' }
    );

    // Return response
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