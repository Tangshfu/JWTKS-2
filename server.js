const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('totally_not_my_privateKeys.db');
const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}

function createTable(){
  db.run(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
   )`);
}

function generateToken(nowkeyPair) {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: nowkeyPair.kid
    }
  };

  var token = jwt.sign(payload, nowkeyPair.toPEM(true), options);
  return token;
}

function generateExpiredJWT(nowexpiredKeyPair) {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: nowexpiredKeyPair.kid
    }
  };

  var expiredToken = jwt.sign(payload, nowexpiredKeyPair.toPEM(true), options);
  return expiredToken;
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  db.all(`SELECT * FROM keys`,async(err, rows) => {
    if (err) {
      res.json({"err":err});
    } else {
      var data=rows;
      var data_list=[];
      for(var i=0;i<data.length;i++){
        let jwkKey = await jose.JWK.asKey(data[i].key, 'pem');
        const validKeys = [jwkKey].filter(key => !key.expired);
        if(data[i].exp>Math.floor(Date.now() / 1000)){
          data_list.push({"keys": validKeys.map(key => key.toJSON()) })
        }
      }
      res.json({"data_list":data_list});
    }
  })
});

app.post('/auth', (req, res) => {
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [keyPair.toPEM(true), Math.floor(Date.now() / 1000) + 3600]); 
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [expiredKeyPair.toPEM(true), Math.floor(Date.now() / 1000) - 3600]);

  db.all(`SELECT * FROM keys`,async(err, rows) => {
    if (err) {
     return res.json({"err":err});
    } else {
      var data=rows;
      let nowKey="";
      let nowExpiredKey="";
      for(var i=0;i<data.length;i++){
        let jwkKey = await jose.JWK.asKey(data[i].key, 'pem');
        if(jwkKey.kid.indexOf(keyPair.kid)>=0){
          nowKey=jwkKey;
        }else if(jwkKey.kid.indexOf(expiredKeyPair.kid)>=0){
          nowExpiredKey=jwkKey;
        }
      }
      var token="";
      if (req.query.expired === 'true'){
        token=generateExpiredJWT(nowExpiredKey);
      }else{
        token=generateToken(nowKey);
      }
      return res.send(token);
    }
  });
});

generateKeyPairs().then(() => {
  createTable();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
