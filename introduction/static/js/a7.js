event4 = function () {
    var code = document.getElementById('a7_input').value;
    var myHeaders = new Headers();

    // SECURITY: Do not hardcode JWTs, CSRF tokens, or cookies in client-side code.
    // Any required authentication or CSRF tokens must be issued and managed server-side
    // (e.g., via HttpOnly cookies or server-rendered hidden fields), not embedded here.
    //
    // Example (non-sensitive) usage if needed for the lab:
    // const jwt = window.APP_JWT || null;
    // if (jwt) {
    //     myHeaders.append('Authorization', 'Bearer ' + jwt);
    // }

    var formdata = new FormData();
    // CSRF tokens, if required, should be injected by the backend as hidden inputs
    // or via meta tags and then read here, rather than hardcoded.
    formdata.append('code', code);

    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: formdata,
        redirect: 'follow'
    };

    fetch('/2021/discussion/A7/api', requestOptions)
        .then(response => response.text())
        .then(result => {
            let data = JSON.parse(result); // parse JSON string into object
            console.log(data);
            document.getElementById('a7_d4').style.display = 'flex';
            document.getElementById('a7_d4').innerText = 'Result: ' + data.message;
        })
        .catch(error => console.log('error', error));
};
