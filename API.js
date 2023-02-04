const crypto = require('crypto');
const axios = require('axios');
const os = require('os')
const { execSync, spawnSync } = require('child_process')

const endpoint = "https://api.authspire.com/v1"
var initialized
var variables = [];

class API {
    /**
     * @param {string} [app_name] - Name of your application found in the dashboard
     * @param {string} [userid] - Your userid can be found in your account settings.
     * @param {string} [secret] - Application secret found in the dashboard
     * @param {string} [currentVersion] - Current application version.
     * @param {string} [publicKey] - Your public key for encryption.
    **/
    constructor (app_name, userid, secret, currentVersion, publicKey) {
        if(API.IsEmpty(app_name) || API.IsEmpty(userid) || API.IsEmpty(secret) || API.IsEmpty(currentVersion) || API.IsEmpty(publicKey)) {
            API.Error(InvalidApplication)
        }

        this.app_name = app_name;
        this.userid = userid;
        this.secret = secret;
        this.currentVersion = currentVersion;
        this.publicKey = Encryption.FormatPublicKey(publicKey);
    };


    Initialize = () => new Promise(async (resolve) => {
        this.key = randomString(32);
        this.iv = randomString(16);
       
        const data = {
            action: Buffer.from("app_info").toString("base64"),
            userid: Buffer.from(this.userid).toString("base64"),
            app_name: Buffer.from(this.app_name).toString("base64"),
            secret: Encryption.AESEncrypt(this.secret, this.key, this.iv),
            version: Encryption.AESEncrypt(this.currentVersion, this.key, this.iv),
            hash: this.your_hash_here, //Encryption.AESEncrypt(this.your_hash, this.key, this.iv), to use with your hash
            key: Encryption.RSAEncrypt(this.key, this.publicKey),
            iv: Encryption.RSAEncrypt(this.iv, this.publicKey)
        };

        let response = await Post(data);

        if (response.status == "success") {
            this.application_status = Encryption.AESDecrypt(response.application_status, this.key, this.iv);
            this.application_hash = Encryption.AESDecrypt(response.application_hash, this.key, this.iv);
            this.application_name = Encryption.AESDecrypt(response.application_name, this.key, this.iv);
            this.application_version = Encryption.AESDecrypt(response.application_version, this.key, this.iv);
            this.application_update_url = Encryption.AESDecrypt(response.update_url, this.key, this.iv);
            this.application_user_count = Encryption.AESDecrypt(response.user_count, this.key, this.iv);

            initialized = true;
        }
        else if (response.status == "update_available") {
            this.update_url = Encryption.AESDecrypt(response.update_url, this.key, this.iv);
            this.application_version = Encryption.AESDecrypt(response.application_version, this.key, this.iv);

            API.UpdateApplication(this.update_url, this.application_version)
            return resolve(false);
        }
        else if (response.status == "invalid_hash") {
            Error(ApplicationManipulated);
            return resolve(false);
        }
        else if (response.status == "invalid_app") {
            Error(InvalidApplication);
            return resolve(false);
        }
        else if (response.status == "paused") {
            Error(ApplicationPaused);
            return resolve(false);
        }
        else if (response.status == "locked") {
            Error(ApplicationDisabled);
            return resolve(false);
        }

        resolve(true);
    })



    Login = (username, password) => new Promise(async (resolve) => {
        if(!initialized) {
            Error(NotInitialized);
            return resolve(false);
        }

        if(!(username || password)) {
            Error(NotInitialized);
            return resolve(false);
        }

        this.key = randomString(32);
        this.iv = randomString(16);

        const data = {
            action: Buffer.from("login").toString("base64"),
            userid: Buffer.from(this.userid).toString("base64"),
            app_name: Buffer.from(this.app_name).toString("base64"),
            secret: Encryption.AESEncrypt(this.secret, this.key, this.iv),
            username: Encryption.AESEncrypt(username, this.key, this.iv),
            password: Encryption.AESEncrypt(password, this.key, this.iv),
            hwid: Encryption.AESEncrypt(API.GetUniqueId(), this.key, this.iv),
            key: Encryption.RSAEncrypt(this.key, this.publicKey),
            iv: Encryption.RSAEncrypt(this.iv, this.publicKey)
        };

        let response = await Post(data);
        

        if(response.status == "ok") {
            this.user_username = Encryption.AESDecrypt(response.username, this.key, this.iv);
            this.user_email = Encryption.AESDecrypt(response.email, this.key, this.iv);
            this.user_ip = Encryption.AESDecrypt(response.ip, this.key, this.iv);
            this.user_expires = Encryption.AESDecrypt(response.expires, this.key, this.iv);
            this.user_hwid = Encryption.AESDecrypt(response.hwid, this.key, this.iv);
            this.user_last_login = Encryption.AESDecrypt(response.last_login, this.key, this.iv);
            this.user_created_at = Encryption.AESDecrypt(response.created_at, this.key, this.iv);
            this.user_variable = Encryption.AESDecrypt(response.variable, this.key, this.iv);
            this.user_level = Encryption.AESDecrypt(response.level, this.key, this.iv);
            let app_variables = Encryption.AESDecrypt(response.app_variables, this.key, this.iv);
            app_variables.split(";").forEach(function(app_variable) {
                let app_variable_split = app_variable.split(";");
                try {
                    variables.push(app_variable_split[0], app_variable_split[1]);
                } catch { }
            });

        } else if(response.status == "invalid_user") {
            Error(InvalidUserCredentials)
            return resolve(false)
        } else if(response.status == "invalid_details") {
            Error(InvalidUserCredentials)
            return resolve(false)
        } else if(response.status == "license_expired") {
            Error(UserLicenseExpired)
            return resolve(false)
        } else if(response.status == "invalid_hwid") {
            Error(UserLicenseTaken)
            return resolve(false)
        } else if(response.status == "banned") {
            Error(UserBanned)
            return resolve(false)
        } else if(response.status == "blacklisted") {
            Error(UserBlacklisted)
            return resolve(false)
        } else if(response.status == "vpn_blocked") {
            Error(VPNBlocked)
            return resolve(false)
        }

        return resolve(true)

    })

    Register = (username, password, license, email) => new Promise(async (resolve) => {
        if(!initialized) {
            Error(NotInitialized);
            return resolve(false);
        }

        if(!(username || password || license || email)) {
            Error(InvalidLogInfo);
            return resolve(false);
        }

        this.key = randomString(32);
        this.iv = randomString(16);

        const data = {
            action: Buffer.from("register").toString("base64"),
            userid: Buffer.from(this.userid).toString("base64"),
            app_name: Buffer.from(this.app_name).toString("base64"),
            secret: Encryption.AESEncrypt(this.secret, this.key, this.iv),
            username: Encryption.AESEncrypt(username, this.key, this.iv),
            password: Encryption.AESEncrypt(password, this.key, this.iv),
            license: Encryption.AESEncrypt(license, this.key, this.iv),
            email: Encryption.AESEncrypt(email, this.key, this.iv),
            hwid: Encryption.AESEncrypt(API.GetUniqueId(), this.key, this.iv),
            key: Encryption.RSAEncrypt(this.key, this.publicKey),
            iv: Encryption.RSAEncrypt(this.iv, this.publicKey)
        };

        let response = await Post(data);
        
        if(response.status == "user_added") {
            return resolve(true)
        } else if(response.status == "invalid_details") {
            Error(RegisterInvalidDetails)
            return resolve(false)
        } else if(response.status == "email_taken") {
            Error(RegisterEmailTaken)
            return resolve(false)
        } else if(response.status == "invalid_license") {
            Error(RegisterInvalidLicense)
            return resolve(false)
        } else if(response.status == "user_already_exists") {
            Error(UserExists)
            return resolve(false)
        } else if(response.status == "blacklisted") {
            Error(UserBlacklisted)
            return resolve(false)
        } else if(response.status == "vpn_blocked") {
            Error(VPNBlocked)
            return resolve(false)
        }

        return resolve(true)

    });


    License = (license) => new Promise(async (resolve) => {
        if(!initialized) {
            Error(NotInitialized);
            return resolve(false);
        }

        if(!(license)) {
            Error(InvalidLoginInfo);
            return resolve(false);
        }

        this.key = randomString(32);
        this.iv = randomString(16);

        const data = {
            action: Buffer.from("license").toString("base64"),
            userid: Buffer.from(this.userid).toString("base64"),
            app_name: Buffer.from(this.app_name).toString("base64"),
            secret: Encryption.AESEncrypt(this.secret, this.key, this.iv),
            license: Encryption.AESEncrypt(license, this.key, this.iv),
            hwid: Encryption.AESEncrypt(API.GetUniqueId(), this.key, this.iv),
            key: Encryption.RSAEncrypt(this.key, this.publicKey),
            iv: Encryption.RSAEncrypt(this.iv, this.publicKey)
        };

        let response = await Post(data);
        
        if(response.status == "ok") {

            this.user_username = Encryption.AESDecrypt(response.username, this.key, this.iv);
            this.user_email = Encryption.AESDecrypt(response.email, this.key, this.iv);
            this.user_ip = Encryption.AESDecrypt(response.ip, this.key, this.iv);
            this.user_expires = Encryption.AESDecrypt(response.expires, this.key, this.iv);
            this.user_hwid = Encryption.AESDecrypt(response.hwid, this.key, this.iv);
            this.user_last_login = Encryption.AESDecrypt(response.last_login, this.key, this.iv);
            this.user_created_at = Encryption.AESDecrypt(response.created_at, this.key, this.iv);
            this.user_variable = Encryption.AESDecrypt(response.variable, this.key, this.iv);
            this.user_level = Encryption.AESDecrypt(response.level, this.key, this.iv);
            let app_variables = Encryption.AESDecrypt(response.app_variables, this.key, this.iv);
            app_variables.split(";").forEach(function(app_variable) {
                let app_variable_split = app_variable.split(":");
                try {
                    variables.push(app_variable_split);
                } catch { }
            });

            return resolve(true)
        } else if(response.status == "invalid_user") {
            Error(InvalidUserCredentials)
            return resolve(false)
        } else if(response.status == "user_limit_reached") {
            Error(UserLimitReached)
            return resolve(false)
        } else if(response.status == "invalid_license") {
            Error(RegisterInvalidLicense)
            return resolve(false)
        } else if(response.status == "license_expired") {
            Error(UserLicenseExpired)
            return resolve(false)
        } else if(response.status == "invalid_hwid") {
            Error(UserLicenseTaken)
            return resolve(false)
        } else if(response.status == "banned") {
            Error(UserBanned)
            return resolve(false)
        } else if(response.status == "license_taken") {
            Error(UserLicenseTaken)
            return resolve(false)
        } else if(response.status == "blacklisted") {
            Error(UserBlacklisted)
            return resolve(false)
        } else if(response.status == "vpn_blocked") {
            Error(VPNBlocked)
            return resolve(false)
        }

        return resolve(true)
        
    });


    AddLog = (username, action) => new Promise(async (resolve) => {
        if(!initialized) {
            Error(NotInitialized);
            return resolve(false);
        }

        if(!(username || action)) {
            Error(InvalidLoginInfo);
            return resolve(false);
        }

        this.key = randomString(32);
        this.iv = randomString(16);
        
        const data = {
            action: Buffer.from("log").toString("base64"),
            userid: Buffer.from(this.userid).toString("base64"),
            app_name: Buffer.from(this.app_name).toString("base64"),
            secret: Encryption.AESEncrypt(this.secret, this.key, this.iv),
            username: Encryption.AESEncrypt(username, this.key, this.iv),
            user_action: Encryption.AESEncrypt(action, this.key, this.iv),
            key: Encryption.RSAEncrypt(this.key, this.publicKey),
            iv: Encryption.RSAEncrypt(this.iv, this.publicKey)
        };

        let response = await Post(data);

        if (response.status == "log_added") {
            return resolve(true)
        }
        else if (response.status == "failed") {
            Error(FailedToAddLog)
            return resolve(false)
        }
        else if (response.status == "invalid_log_info") {
            Error(InvalidLogInfo)
            return resolve(false)
        }
        else if (response.status == "log_limit_reached") {
            Error(LogLimitReached);
            return resolve(false);
        }

        resolve(true);
    })


    GetVariable = (secret) => new Promise(async (resolve) => {
        if(!initialized) {
            Error(NotInitialized);
            return resolve(false);
        }

        for (let index = 0; index < variables.length; index++) {
           if(variables[index][0] == secret) {
                resolve(variables[index][1]);
           }
            
        }
    });

    static UpdateApplication(url, version) {
        if (os.platform() != 'win32') return

        const msg = `Update ${version} available!`;

        spawnSync("powershell.exe", [`
Add-Type -AssemblyName PresentationCore,PresentationFramework;
[System.Windows.MessageBox]::Show('${msg}');
`]);

        execSync("start " + url)
    }


    static IsEmpty(input) {
        if (input == '') {
            return true
        } else {
            return false
        }
    }

    static GetUniqueId() {
        if (os.platform() != 'win32') return false
        const cmd = execSync('wmic useraccount where name="%username%" get sid').toString('utf-8')
        const system_id = cmd.split('\n')[1].trim()
        return system_id
    }
}


function Error(msg) {
    console.log(msg)
    return process.exit(-1)
}

function Post(data) {
    return new Promise(async (resolve) => {
        const request = await axios({
          method: 'POST',
          url: endpoint,
          data: new URLSearchParams(data).toString()
        }).catch((err) => {
          Misc.error(err)
        })
    
        if (request && request.data) {
          resolve(request.data)
        } else {
          resolve(null)
        }
      })
}

class Encryption {
    static RSAEncrypt(input, key) {
        var buffer = Buffer.from(input)
        var encrypted = crypto.publicEncrypt({ key: key, padding: crypto.constants.RSA_PKCS1_PADDING,}, buffer)
        return encrypted.toString("base64")
    }

    static AESDecrypt(input_enc, key, iv) {
        const cipher = crypto.createDecipheriv("aes-256-cbc", key, iv)
        let dec = cipher.update(input_enc, "base64", "utf-8")
        dec += cipher.final("utf-8")
        return dec
    }

    static AESEncrypt(input, key, iv) {
        const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
        let enc = cipher.update(input, "utf-8", "base64")
        enc += cipher.final("base64")
        return enc
    }

    static FormatPublicKey(publicKey) {
        let finalPublicKey = "-----BEGIN PUBLIC KEY-----\n"
        const chunks = publicKey.match(/.{1,64}(?:\s|)/g);

        chunks.forEach((chunk, index) => {
            finalPublicKey += chunk + "\n"
        })
        finalPublicKey += "-----END PUBLIC KEY-----"
        return finalPublicKey
    }
}

const randomString = (length = 8) => {
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let str = '';
    for (let i = 0; i < length; i++) {
        str += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return str;
};

const ServerOffline = "Server is currently not responding, try again later!";
const RegisterInvalidLicense = "The license you entered is invalid or already taken!";
const RegisterInvalidDetails = "You entered an invalid username or email!";
const RegisterUsernameTaken = "This username is already taken!";
const RegisterEmailTaken = "This email is already taken!";
const UserExists = "A user with this username already exists!";
const UserLicenseTaken = "This license is already binded to another machine!";
const UserLicenseExpired = "Your license has expired!";
const UserBanned = "You have been banned for violating the TOS!";
const UserBlacklisted = "Your IP/HWID has been blacklisted!";
const VPNBlocked = "You cannot use a vpn with our service! Please disable it.";
const InvalidUser = "User doesn't exist!";
const InvalidUserCredentials = "Username or password doesn't match!";
const InvalidLoginInfo = "Invalid login information!";
const InvalidLogInfo = "Invalid log information!";
const LogLimitReached = "You can only add a maximum of 50 logs as a free user, upgrade to premium to enjoy no log limits!";
const UserLimitReached = "You can only add a maximum of 30 users as a free user, upgrade to premium to enjoy no user limits!";
const FailedToAddLog = "Failed to add log, contact the provider!";
const InvalidApplication = "Application could not be initialized, please check your secret and userid.";
const ApplicationPaused = "This application is currently under construction, please try again later!";
const NotInitialized = "Please initialize your application first!";
const NotLoggedIn = "Please log into your application first!";
const ApplicationDisabled = "Application has been disabled by the provider.";
const ApplicationManipulated = "File corrupted! This program has been manipulated or cracked. This file won't work anymore.";

module.exports = API
