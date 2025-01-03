document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const totp = document.getElementById("totp_code").value.trim();


    var errorMsg = '';
    if (!username || !totp || !password) {
        errorMessage.textContent = "All fields must be filled";
        return;
    }

    if (username.length < 3 || username.length > 40){
        errorMsg = "Username must be between 3 and 40 characters | ";
    }

    const usernameRegex = /^[a-z][a-z0-9]*$/;
    if (!usernameRegex.test(username)){
        errorMsg += "Only lower letters and digits are permitted for username (first character must be a letter) | ";
    }
    
    const totpRegex = /^[0-9]{6}$/;
    if (!totpRegex.test(totp)){
        errorMsg += "Invalid TOTP format";
    }

    if (errorMsg){
        errorMessage.textContent = errorMsg;
        return;
    }

    this.submit();
});