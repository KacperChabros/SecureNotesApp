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