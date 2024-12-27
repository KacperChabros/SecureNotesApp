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


document.getElementById("addNoteForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const title = document.getElementById("title").value.trim();
    const content = document.getElementById("content").value.trim();
    const sharedToUsername = document.getElementById("sharedToUsername").value.trim();
    const note_password = document.getElementById("note_password").value;
    const note_password_repeat = document.getElementById("note_password_repeat").value;
    const user_password = document.getElementById("user_password").value;
    const totp_code = document.getElementById("totp_code").value;


    errorMessage.textContent = "";
            
    var errorMsg = '';
    if (!title || !content) {
        errorMsg += "Title and Content fields are required | ";
    }

    if (title.length < 4 || title.length > 50){
        errorMsg += "Title must be between 4 and 50 characters | ";
    }

    if (content.length < 5 || title.length > 2500){
        errorMsg += "Content must be between 5 and 2500 characters | ";
    }

    if (sharedToUsername && (sharedToUsername.length < 3 || sharedToUsername.length > 40)){
        errorMsg += "If set, Username must be between 3 and 40 characters | ";
    }
            
    if ((note_password && !note_password_repeat) || (!note_password && note_password_repeat)) {
        errorMsg += "Both note password and note password repeat must be provided when one is | ";
    }

    if (note_password && note_password_repeat){
        if (note_password && note_password.length < 12){
            errorMsg += "If set, note password cannot be shorter than 12 characters | ";
        }

        if(note_password &&  !hasLowerCase.test(note_password)){
            errorMsg +="Note Password must contain a lowercase | ";
        }
        if(note_password && !hasUpperCase.test(note_password)){
            errorMsg +="Note Password must contain an uppercase | ";
        }
        if(note_password && !hasDigit.test(note_password)){
            errorMsg +="Note Password must contain a digit | ";
        }
        if(note_password && !hasSpecialChar.test(note_password)){
            errorMsg +="Note Password must contain a special character | ";
        }
                
        const entropy = calculateEntropy(note_password);
        if (entropy < 59){
            errorMsg += "Note Password is too weak | ";
        }
                
        if (note_password !== note_password_repeat) {
            errorMsg += "Note Passwords do not match | ";
        }
    } 

    if (totp_code.length != 6){
        errorMsg += "Invalid TOTP format";
    }

    if (errorMsg){
        errorMessage.textContent = errorMsg;
        return;
    }

    this.submit();
});

document.getElementById("note_password").addEventListener("keyup", () => {
    const password = document.getElementById("note_password").value;
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