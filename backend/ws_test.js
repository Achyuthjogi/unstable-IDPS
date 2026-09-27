const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:8000/ws', ['idps_demo_key']);
ws.on('message', (data) => {
    console.log(data.toString());
    process.exit(0);
});
ws.on('error', (e) => {
    console.log("Error:", e.message);
    process.exit(1);
});
