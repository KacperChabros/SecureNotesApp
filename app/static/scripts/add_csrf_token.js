fetch('/get_csrf_token')
    .then(response => response.json())
    .then(data => {
        document.getElementById('csrf_token').value = data.csrf_token;
    });