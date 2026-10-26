const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");

const app = express();
const PORT = 3000;

// Read form data and serve HTML files from the public folder.
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Keep the MySQL password outside the submitted source code.
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: process.env.ROOTPASS,
    database: "unihub",
    port: 3306
});

connection.connect(function (err) {
    if (err) {
        console.log("Could not connect to MySQL:", err.message);
        return;
    }

    console.log("Database connection established");
});

function page(message, linkText, linkAddress) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>UniHub</title>
            <style>
                body {
                    margin: 0;
                    min-height: 100vh;
                    display: grid;
                    place-items: center;
                    background: #f4f7fb;
                    color: #172033;
                    font-family: Arial, sans-serif;
                }
                main {
                    width: min(420px, calc(100% - 48px));
                    padding: 32px;
                    background: white;
                    border-radius: 16px;
                    box-shadow: 0 12px 32px rgba(28, 49, 82, 0.12);
                    text-align: center;
                }
                a { color: #3157d5; font-weight: bold; }
            </style>
        </head>
        <body>
            <main>
                <h1>UniHub</h1>
                <p>${message}</p>
                <a href="${linkAddress}">${linkText}</a>
            </main>
        </body>
        </html>`;
}

// Registration endpoint required by the assignment.
app.post("/register", function (req, res) {
    const username = req.body.username?.trim();
    const email = req.body.email?.trim();
    const plainPassword = req.body.password;

    if (!username || !email || !plainPassword) {
        return res.status(400).send(
            page("Please enter a username, email and password.", "Return to registration", "register.html")
        );
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = crypto
        .pbkdf2Sync(plainPassword, salt, 100000, 64, "sha512")
        .toString("hex");

    const sql = "INSERT INTO accounts (username, email, password, salt) VALUES (?, ?, ?, ?)";

    connection.query(sql, [username, email, hashedPassword, salt], function (err) {
        if (err) {
            if (err.code === "ER_DUP_ENTRY") {
                return res.status(409).send(
                    page("That username or email is already registered.", "Return to registration", "register.html")
                );
            }

            console.log("Registration error:", err);
            return res.status(500).send(
                page("Registration could not be completed.", "Return to registration", "register.html")
            );
        }

        res.send(
            page("You have successfully registered.", "Go to the login page", "login.html")
        );
    });
});

// Login endpoint required by the assignment.
app.post("/login", function (req, res) {
    const username = req.body.username?.trim();
    const plainPassword = req.body.password;

    if (!username || !plainPassword) {
        return res.status(401).send(
            page("The login credentials were incorrect.", "Go back to login", "login.html")
        );
    }

    const sql = "SELECT username, password, salt FROM accounts WHERE username = ?";

    connection.query(sql, [username], function (err, results) {
        if (err) {
            console.log("Login error:", err);
            return res.status(500).send(
                page("The login request could not be completed.", "Go back to login", "login.html")
            );
        }

        if (results.length === 0) {
            return res.status(401).send(
                page("The login credentials were incorrect.", "Go back to login", "login.html")
            );
        }

        const account = results[0];
        const submittedHash = crypto
            .pbkdf2Sync(plainPassword, account.salt, 100000, 64, "sha512")
            .toString("hex");

        const storedBuffer = Buffer.from(account.password, "hex");
        const submittedBuffer = Buffer.from(submittedHash, "hex");
        const passwordMatches =
            storedBuffer.length === submittedBuffer.length &&
            crypto.timingSafeEqual(storedBuffer, submittedBuffer);

        if (!passwordMatches) {
            return res.status(401).send(
                page("The login credentials were incorrect.", "Go back to login", "login.html")
            );
        }

        res.send(
            page(`You have logged in successfully, ${username}.`, "Go back to login", "login.html")
        );
    });
});

app.listen(PORT, function () {
    console.log(`Server running at http://localhost:${PORT}`);
});
