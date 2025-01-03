document.getElementById("forgotPasswordForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();

    errorMessage.textContent = "";
    
    if (!username || !email) {
        errorMessage.textContent = "All fields must be filled";
        return;
    }

    var errorMsg = "";
    if (username.length < 3 || username.length > 40){
        errorMsg = "Username must be between 3 and 40 characters | ";
    }

    const usernameRegex = /^[a-z][a-z0-9]*$/;
    if (!usernameRegex.test(username)){
        errorMsg += "Only lower letters and digits are permitted for username (first character must be a letter) | ";
    }

    if(email.length < 6 || email.length > 320){
        errorMsg += "Email must be between 6 and 320 characters | ";
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/; //owasp email regex
    if (!emailRegex.test(email)) {
        errorMsg += "Email address is invalid | ";
    }

    if(errorMsg){
        errorMessage.textContent = errorMsg;
        return;
    }

    this.submit();
});