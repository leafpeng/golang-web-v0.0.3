document.addEventListener("DOMContentLoaded", () => {

    const load = function() {
        if(!window.location.hash) {
            window.location = window.location + '#-_-';
            window.location.reload();
        }
    };
    setTimeout(load, 750);
     


    let conn;
    let msg = document.querySelector("#msg");
    let log = document.querySelector("#log");

    const appendLog = (item) => {
        let doScroll = log.scrollTop > log.scrollHeight - log.clientHeight - 1;
        log.appendChild(item);
        if (doScroll) {
            log.scrollTop = log.scrollHeight - log.clientHeight;
        }
    }
    document.querySelector("#form").onsubmit = () => {
        if (!conn) {
            return false;
        }
        if (!msg.value) {
            return false;
        }
        conn.send(msg.value);
        msg.value = "";
        return false;

    };

    if (window["WebSocket"]) {
        conn = new WebSocket(`ws://${document.location.host}/ws`);
        conn.onclose = (evt) => {
            let item = document.createElement("div");
            item.innerHTML = "<b>Connection closed.</b>";
            appendLog(item);
        };
        conn.onmessage = (evt) => {
            let messages = evt.data.split('\n');

            for (let i = 0; i < messages.length; i++) {
                let item = document.createElement("div");
                item.innerHTML = messages[i];
                appendLog(item);
            }
        };
    } else {
        let item = document.createElement("div");
        item.innerHTML = "<b>Your browser does not support WebSockets.</b>";
        appendLog(item);
    }
    
})
