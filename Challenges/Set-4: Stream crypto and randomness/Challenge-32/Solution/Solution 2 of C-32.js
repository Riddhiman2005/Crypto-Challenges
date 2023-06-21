
// Java-Script Code for Challenge-32
// Code by @Sumana89


const http = require('http');
const crypto = require('crypto');

const SLEEP_US = 5000;
const PORT = 8081;

function httpmain() {
  // Open socket
  const server = http.createServer((req, res) => {
    const RES_200 = "OK";
    const RES_500 = "Internal Server Error";

    if (req.url.startsWith("/test?file=")) {
      const data = req.url.substring(15).split("&")[0];
      const macstr = req.url.substring(15).split("&")[1];

      // Check for MAC
      if (!macstr) {
        res.writeHead(500, RES_500);
        res.end();
        return;
      }

      const mac = macstr.substring(0, 40);
      const l = data.length;
      const k = Buffer.from(Array(64).fill().map(() => Math.floor(Math.random() * 256)));

      const hmac = crypto.createHmac("sha1", k);
      hmac.update(data);
      const calcmac = hmac.digest();

      let i;
      for (i = 0; i < 20; i++) {
        if (mac[i] !== calcmac[i]) break;
        usleep(SLEEP_US);
      }

      if (i === 20) {
        res.writeHead(200, RES_200);
        res.end();
        return;
      }
    }

    res.writeHead(500, RES_500);
    res.end();
  });

  server.listen(PORT, '127.0.0.1', () => {
    // Get random key
    const k = Array(64).fill().map(() => Math.floor(Math.random() * 256));

    // Print result cheats xd lol
    const hmac = crypto.createHmac("sha1", Buffer.from(k));
    hmac.update("example_file.bin");
    const res = hmac.digest();

    console.log("Result:");
    console.log(res.toString('hex'));
  });
}

function connectSocket(address, port, callback) {
  const socket = new net.Socket();

  socket.connect(port, address, () => {
    callback(null, socket);
  });

  socket.on('error', (error) => {
    callback(error, null);
  });

  socket.on('close', () => {
    // Handle socket close event if needed
  });
}

function discoverHMAC() {
  // Discover HMAC
  const file = "example_file.bin";
  let buf = `GET /test?file=${file}&${"0".repeat(40)} HTTP/1.1`;
  let l = buf.length;

  let hmac = buf.indexOf("&") + 1;
  buf = buf.slice(0, hmac) + "0".repeat(40) + buf.slice(hmac + 40);

  // Setup socket
  const address = "127.0.0.1";
  const sock = connectSocket(address, PORT, (error, socket) => {
    if (error) {
      console.error("Can't reach server");
      return;
    }

    let tmp;
    let k_i, byte;
    for (k_i = 0; k_i < 20; k_i++) {
      let hexptr = hmac + k_i * 2;
      let mtbyte = 0; // Most time byte
      let mt = 0; // Most time

      process.stdout.write("00");
      for (byte = 0; byte < 256; byte++) {
        // Generate next URL
        tmp = hexptr.substring(2, 4);
        hexptr = hexptr.slice(0, 2) + byte.toString(16).padStart(2, "0") + tmp;
        process.stdout.write(`\b\b${byte.toString(16).padStart(2, "0")}`);

        let tval_result = 0;
        let flag = 0;

        for (let j = 0; j < 5; j++) {
          let client = connectSocket(address, PORT, (error, socket) => {
            if (error) {
              console.error("Can't connect");
              return;
            }

            const tval_before = process.hrtime.bigint();
            socket.write(buf);
            const data = socket.read(128);
            const tval_after = process.hrtime.bigint();

            socket.destroy();

            if (k_i === 19) {
              if (data.toString().startsWith("HTTP/1.1 200")) {
                mtbyte = byte;
                flag = 1;
                break;
              }
            }
            tval_result += Number(tval_after - tval_before);
          });

          client.on('error', (error) => {
            console.error("Can't connect");
            return;
          });
        }

        if (flag) break;
        if (tval_result > mt) {
          mt = tval_result;
          mtbyte = byte;
        }
      }

      process.stdout.write(`\b\b${mtbyte.toString(16).padStart(2, "0")}`);
      tmp = hexptr.substring(2, 4);
      hexptr = hexptr.slice(0, 2) + mtbyte.toString(16).padStart(2, "0") + tmp;
    }
    console.log();

    /// Check HMAC
    const client = connectSocket(address, PORT, (error, socket) => {
      if (error) {
        console.error("Can't connect");
        return;
      }

      socket.write(buf);
      const data = socket.read(128);
      if (data.toString().startsWith("HTTP/1.1 200")) console.log("OK");
      else console.log("FAIL");

      socket.destroy();
    });
  });

  process.on('SIGINT', () => {
    sock.destroy();
    process.exit();
  });
}

// Fork HTTP server subprocess
const child_process = require('child_process');
const httppid = child_process.fork(httpmain);

discoverHMAC();

process.on('SIGINT', () => {
  httppid.kill();
  process.exit();
});
