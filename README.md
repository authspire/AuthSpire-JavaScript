
<h1 align="center">
  <br>
  <a href="https://authspire.com"><img src="https://i.ibb.co/KxvFZ5B/logo.png" alt="AuthSpire" width="200"></a>
  <br>
  AuthSpire
  <br>
</h1>

<h4 align="center">A FREE and secure licensing & authentication solution<br>using hybrid encryption.</h4>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#functions">API Functions</a> •
</p>

<div align="center">
    <img src="https://media.giphy.com/media/V6v60D0r4St0xXNJqo/giphy.gif" width="450"> 
</div>


## Key Features

* License your software / application
  - Restrict access from other users and increase security
* Manage Users
  - See who uses your application, set expiry dates for your licenses & more
* Variables
  - Set custom hidden variables that are secured on our server and can not be cracked
* Blacklists
  - Block users by IP or a Unique Identifier from accessing your application
* Logging
  - Handle all logs and see what is happening inside of your application
* Hybrid Encryption System
  - Encryption combined using AES 256 (Advanced Encryption Standard) and RSA to ensure the most security

## How To Use

Download the repository on your system. To compile you can use NodeJS.

Create an account on the <a href="https://authspire.com/sign-up">AuthSpire</a> website.
Create your application.


In the Project you will find this piece of code which is used to identify your application.

<br>
<br>
Name: Name of your application in the dashboard<br>
UserID: UserID found in your account page<br>
Secret: Secret of your application in the dashboard<br>
Version: Version 1.0 by default (for updates change the version accordingly)<br>
Public Key: Public Key for encryption found in the dashboard<br>
<br>

<img src="https://i.ibb.co/HtVJSWs/init.png">

## Functions

<b>Initializing your application</b>

Before using any other functions it is necessary to initialize your application with our server and retrieve all data.
This can be done by calling this method.

<img src="https://i.ibb.co/XtfdZ4N/initialize.png">

<b>Register a user</b>

To register and add a new user to your application you will first require a valid license key which you can generate in 
your authspire dashboard in your selected application.

Register a user by calling this method and validate the registration

<img src="https://i.ibb.co/jGqNYKQ/register.png">


<b>Authenticate a user</b>

To login and add retrieve all user data you can call this method

<img src="https://i.ibb.co/NZcmHfm/login.png">


<b>Adding logs</b>

Sometimes it is necessary to have an overview of what is going on inside your application. For that you can use logs

To add a log you can call this method.

<img src="https://i.ibb.co/qgF7r1d/addlog.png">

<b>Getting Variables</b>

You can store server-sided strings. Your application can then retrieve these strings with a secret key that will be generated in your panel
when you generate your variable. This protects your strings from being decompiled or cracked.

<img src="https://i.ibb.co/0m4nFmq/variable.png">

<b>Authenticate with only a license</b>

Sometimes you want to keep it simple. A user can register/login with only using a license. For this you can use this function

<img src="https://i.ibb.co/KxQhjRm/license.png">

## License

MIT
