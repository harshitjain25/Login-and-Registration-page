UNIHUB REGISTRATION AND LOGIN ASSIGNMENT
Harshit Jain

FILES
-----
loginsampleclean.js       Node.js, Express and MySQL server
schema.sql                Creates the accounts table
public/register.html      Registration form
public/login.html         Login form
public/styles.css         Page styling
package.json              Project packages and start command

SETUP
-----
1. Open MySQL Workbench.
2. Open schema.sql and execute the complete file.
3. Open Terminal and change into this assignment folder.
4. Install the packages:

   npm install

5. Store your MySQL root password temporarily in the terminal session:

   export ROOTPASS='YOUR_MYSQL_PASSWORD'

   Replace YOUR_MYSQL_PASSWORD locally. Do not submit or share your password.

6. Start the server:

   npm start

7. Open the registration page:

   http://localhost:3000/register.html

TESTING
-------
1. Register using a username, email and password.
2. Confirm the message: "You have successfully registered."
3. Click the login link.
4. Enter the same username and password.
5. Confirm the message: "You have logged in successfully."
6. Enter an incorrect password.
7. Confirm the message: "The login credentials were incorrect."
8. Confirm that the response includes a link back to login.html.

DATABASE CHECK
--------------
Run this in MySQL Workbench:

USE unihub;
SELECT user_id, username, email, created_at FROM accounts;

STOPPING THE SERVER
-------------------
Return to Terminal and press Control + C.

IMPORTANT
---------
Always open the pages through http://localhost:3000. Do not open the HTML files
directly using file:/// because the form must be processed by the Node server.
