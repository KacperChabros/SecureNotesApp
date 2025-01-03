document.getElementById("cipheredNoteForm").addEventListener("submit", function (event) {
    event.preventDefault();

    const errorMessage = document.getElementById("errorMessage");
    const notePassword = document.getElementById("note_password").value;

    errorMessage.textContent = "";

    var errorMsg = "";

    if(!notePassword){
        errorMsg = "Note password must be provided"
    }

    if(errorMsg){
        errorMessage.textContent = errorMsg;
        return;
    }

    this.submit();
});