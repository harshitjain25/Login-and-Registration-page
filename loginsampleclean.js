const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;

// Make sure a session secret was provided before starting the server.
if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET environment variable is required.");
    process.exit(1);
}

// Read submitted form data.
app.use(express.urlencoded({ extended: true }));

// Read cookies sent by the browser.
app.use(cookieParser());

// Configure login sessions.
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 60 * 60 * 1000, // Session expires after one hour.
            httpOnly: true,
            secure: false, // False because the assignment uses localhost.
            sameSite: "lax"
        }
    })
);

// Serve HTML and CSS files from the public folder.
app.use(express.static("public"));

// Connect to the UniHub MySQL database.
// The MySQL password is stored in the ROOTPASS environment variable.
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: process.env.ROOTPASS,
    database: "unihub",
    port: 3306
});

// Test the database connection.
connection.connect(function (err) {
    if (err) {
        console.log("Could not connect to MySQL:", err.message);
        return;
    }

    console.log("Database connection established");
});

// Create a consistent response page.
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

                a {
                    color: #3157d5;
                    font-weight: bold;
                }
            </style>
        </head>

        <body>
            <main>
                <h1>UniHub</h1>
                <p>${message}</p>
                <a href="${linkAddress}">${linkText}</a>
            </main>
        </body>
        </html>
    `;
}

// Register a new account.
app.post("/register", function (req, res) {
    const username = req.body.username?.trim();
    const email = req.body.email?.trim();
    const plainPassword = req.body.password;

    if (!username || !email || !plainPassword) {
        return res.status(400).send(
            page(
                "Please enter a username, email and password.",
                "Return to registration",
                "register.html"
            )
        );
    }

    // Generate a unique salt and securely hash the password.
    const salt = crypto.randomBytes(16).toString("hex");

    const hashedPassword = crypto
        .pbkdf2Sync(plainPassword, salt, 100000, 64, "sha512")
        .toString("hex");

    const sql =
        "INSERT INTO accounts (username, email, password, salt) VALUES (?, ?, ?, ?)";

    // Parameterized values protect the query from SQL injection.
    connection.query(
        sql,
        [username, email, hashedPassword, salt],
        function (err) {
            if (err) {
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(409).send(
                        page(
                            "That username or email is already registered.",
                            "Return to registration",
                            "register.html"
                        )
                    );
                }

                console.log("Registration error:", err);

                return res.status(500).send(
                    page(
                        "Registration could not be completed.",
                        "Return to registration",
                        "register.html"
                    )
                );
            }

            res.send(
                page(
                    "You have successfully registered.",
                    "Go to the login page",
                    "login.html"
                )
            );
        }
    );
});

// Check the submitted login credentials.
app.post("/login", function (req, res) {
    const username = req.body.username?.trim();
    const plainPassword = req.body.password;

    if (!username || !plainPassword) {
        return res.status(401).send(
            page(
                "The login credentials were incorrect.",
                "Go back to login",
                "login.html"
            )
        );
    }

    const sql =
        "SELECT username, password, salt FROM accounts WHERE username = ?";

    connection.query(sql, [username], function (err, results) {
        if (err) {
            console.log("Login error:", err);

            return res.status(500).send(
                page(
                    "The login request could not be completed.",
                    "Go back to login",
                    "login.html"
                )
            );
        }

        if (results.length === 0) {
            return res.status(401).send(
                page(
                    "The login credentials were incorrect.",
                    "Go back to login",
                    "login.html"
                )
            );
        }

        const account = results[0];

        // Hash the submitted password using the account's stored salt.
        const submittedHash = crypto
            .pbkdf2Sync(
                plainPassword,
                account.salt,
                100000,
                64,
                "sha512"
            )
            .toString("hex");

        const storedBuffer = Buffer.from(account.password, "hex");
        const submittedBuffer = Buffer.from(submittedHash, "hex");

        // Safely compare the submitted password with the stored password.
        const passwordMatches =
            storedBuffer.length === submittedBuffer.length &&
            crypto.timingSafeEqual(storedBuffer, submittedBuffer);

        if (!passwordMatches) {
            return res.status(401).send(
                page(
                    "The login credentials were incorrect.",
                    "Go back to login",
                    "login.html"
                )
            );
        }

        // Store the logged-in username in a session variable.
        req.session.user = {
            username: account.username
        };

        // Save the session before displaying the success page.
        req.session.save(function (sessionError) {
            if (sessionError) {
                console.log("Session error:", sessionError);

                return res.status(500).send(
                    page(
                        "The session could not be created.",
                        "Go back to login",
                        "login.html"
                    )
                );
            }

            res.send(
                page(
                    `You have logged in successfully, ${account.username}.`,
                    "View your profile",
                    "/profile"
                )
            );
        });
    });
});

// Display the username stored in the session.
app.get("/profile", function (req, res) {
    if (!req.session.user) {
        return res.status(401).send(
            page(
                "You are not logged in.",
                "Go to the login page",
                "login.html"
            )
        );
    }

    res.send(
        page(
            `Hello, ${req.session.user.username}. This username came from your session.`,
            "Logout",
            "/logout"
        )
    );
});

// Destroy the session when the user clicks Logout.
app.get("/logout", function (req, res) {
    req.session.destroy(function (err) {
        if (err) {
            console.log("Logout error:", err);

            return res.status(500).send(
                page(
                    "There was an error while logging out.",
                    "Return to profile",
                    "/profile"
                )
            );
        }

        // Remove the session cookie from the browser.
        res.clearCookie("connect.sid");

        res.send(
            page(
                "You have logged out successfully.",
                "Login again",
                "login.html"
            )
        );
    });
});

// Start the Express server.
app.listen(PORT, function () {
    console.log(`Server running at http://localhost:${PORT}`);
});