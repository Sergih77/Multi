// Afegeix aquí el teu codi JavaScript

var key="1";
var pressed=false;
var prova="r";
xhr = new XMLHttpRequest();
url='http://localhost:8000/';
xhr.open("POST", url);


function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

document.addEventListener("keypress", function(event) {
    if(!pressed){
        pressed=true;
        console.log(event.key);
        xhr.send(JSON.stringify({
            letter: event.key,
            page: null
        }));
    }
});

xhr.send(JSON.stringify({
    letter: "prova",
    page: null
}));

xhr.onreadystatechange = (e) => {
    if (xhr.readyState == 4 && xhr.status == 200) {
        document.getElementById("game_data").innerText = xhr.responseText
       // document.getElementById("cookie").innerText = getCookie("session_token")
    }
}