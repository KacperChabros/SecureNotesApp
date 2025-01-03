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

document.getElementById("resetPasswordForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const password = document.getElementById("password").value;
    const passwordRepeat = document.getElementById("password_repeat").value;

    errorMessage.textContent = "";
    
    if (!password || !passwordRepeat) {
        errorMessage.textContent = "All fields must be filled";
        return;
    }

    var errorMsg = "";
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

    const passwordRegex = /^[a-zA-Z0-9 !"#$%&'()*+,\-./:;<=>?@[\]\\^_`{|}~]+$/;
    if(!passwordRegex.test(password)){
        errorMsg += "Password contains an illegal character | ";
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