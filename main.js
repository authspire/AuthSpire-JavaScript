const API = require("./API")

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

const authSpire = new API (
    '', //  Name of your application found in the dashboard
    '', //  Your userid can be found in your account settings.
    '', //  Application secret found in the dashboard
    '1.0', //  Current application version.
    '', //   Your public key for encryption.
);

(async () =>  {
    await authSpire.Initialize();

    console.log(`Application Status: ${authSpire.application_status}`);
    console.log(`Application Name: ${authSpire.application_name}`);
    console.log(`Application Version: ${authSpire.application_version}`);
    console.log(`Application Hash: ${authSpire.application_hash}`);
    console.log(`Update Url: ${authSpire.application_update_url}`);
    console.log(`Total Users: ${authSpire.application_user_count}`);


    readline.question("[1] Register\n[2] Login\n[3] License only\n[4] Add Log\n>> ", async response => {
    
        var username, password, license, email, action

        switch(response) {
            case "1":
                await readline.question("Username: ", async usernameResponse => {
                    username = usernameResponse;
                    await readline.question("Password: ", async passwordResponse => {
                        password = passwordResponse;
                        await readline.question("License: ", async licenseResponse => {
                            license = licenseResponse;
                            await readline.question("Email: ", async emailResponse => {
                                email = emailResponse;
                                let registered = await authSpire.Register(username, password, license, email)
                                if (registered) {
                                    console.log("Registered!");
                                }
                                readline.close();
                            });
                        });
                        
                    });
                });
                break;
            case "2":
                await readline.question("Username: ", async usernameResponse => {
                    username = usernameResponse;
                    await readline.question("Password: ", async passwordResponse => {
                        password = passwordResponse;
                        await authSpire.Login(username, password);
                        YourApplication();
                        readline.close();
                    });
                });
                break;
            case "3":
                await readline.question("License: ", async licenseResponse => {
                    license = licenseResponse;
                    await authSpire.License(license)
                    YourApplication();
                    readline.close();
                });
                break;
            case "4":
                await readline.question("Username: ", async usernameResponse => {
                    username = usernameResponse;
                    await readline.question("Action: ", async actionResponse => {
                        action = actionResponse;
                        await authSpire.AddLog(username, action);
                        console.log("Log added!");
                        readline.close();
                    });
                });
                break;
        }
    });

    async function YourApplication() {
        console.log(`Welcome back ${authSpire.user_username}`);

        console.log("User Data\n")
        console.log(`Username: ${authSpire.user_username}`);
        console.log(`Email: ${authSpire.user_email}`);
        console.log(`Expires: ${authSpire.user_expires}`);
        console.log(`HWID: ${authSpire.user_hwid}`);
        console.log(`Last-Login: ${authSpire.user_last_login}`);
        console.log(`Created-At: ${authSpire.user_created_at}`);
        console.log(`Variable: ${authSpire.user_variable}`);
        console.log(`Level: ${authSpire.user_level}`);
    }
   
})();

