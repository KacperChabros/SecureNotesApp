const hasUpperCase = /[A-Z]/;
const hasLowerCase = /[a-z]/;
const hasDigit = /[0-9]/;
const hasSpecialChar = /[ !"#$%&'()*+,\-./:;<=>?@[\]\\^_`{|}~]/; //owasp list

function calculateEntropy(password) {
    let charSetSize = 0;

    if (hasLowerCase.test(password)) charSetSize += 26;
    if (hasUpperCase.test(password)) charSetSize += 26;
    if (hasDigit.test(password)) charSetSize += 10;
    if (hasSpecialChar.test(password)) charSetSize += 32;

    const passwordLength = password.length;

    return passwordLength > 0 && charSetSize > 0
        ? (passwordLength * Math.log2(charSetSize)).toFixed(2)
        : 0;
}

document.getElementById("registerForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const passwordRepeat = document.getElementById("password_repeat").value;
    // const errorMessage = document.getElementById("errorMessage");
    // const username = he.encode(document.getElementById("username").value.trim(), { useNamedReferences: true });
    // const email = he.encode(document.getElementById("email").value.trim(),{ useNamedReferences: true });
    // const password = document.getElementById("password").value;
    // const passwordRepeat = document.getElementById("password_repeat").value;
    // const username = DOMPurify.sanitize(document.getElementById("username").value.trim(), { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    // const email = DOMPurify.sanitize(document.getElementById("email").value.trim(), { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    //const password = DOMPurify.sanitize(document.getElementById("password").value);
    //const passwordRepeat = DOMPurify.sanitize(document.getElementById("password_repeat").value);

    errorMessage.textContent = "";
    
    if (!username || !email || !password || !passwordRepeat) {
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

    if (password.length < 12) {
        errorMsg += "Password must be at least 12 characters long | ";
    }

    if(!hasLowerCase.test(password)){
        errorMsg +="Password must contain a lowercase | ";
    }
    if(!hasUpperCase.test(password)){
        errorMsg +="Password must contain an uppercase | ";
    }
    if(!hasDigit.test(password)){
        errorMsg +="Password must contain a digit | ";
    }
    if(!hasSpecialChar.test(password)){
        errorMsg +="Password must contain a special character | ";
    }

    const entropy = calculateEntropy(password);
    if (entropy < 59){
        errorMsg += "Password is too weak | ";
    }

    if (password !== passwordRepeat) {
        errorMsg += "Passwords do not match";
    }


    if(errorMsg){
        errorMessage.textContent = errorMsg;
        return;
    }

    this.submit();
});

document.getElementById("password").addEventListener("keyup", () => {
    const password = document.getElementById("password").value;
    const pass_strength = document.getElementById("pass_strength");

    const entropy = calculateEntropy(password);
    var msg = '';
    if (entropy < 35)
        msg = 'Very weak';
    else if (entropy < 59)
        msg = 'Weak';
    else if (entropy < 119)
        msg = 'Strong';
    else
        msg = 'Very strong';
        pass_strength.textContent = msg;
});